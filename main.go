package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type uIntType interface {
	uint | uint16 | uint32 | uint64
}

var handle *pcap.Handle
var err error

type PacketConfig struct {
	Encoding                string `json:"Encoding" binding:"required,encoding"`
	StartOffsetZeroIndex    int    `json:"StartOffsetZeroIndex" binding:"required,gt=0"`
	Length                  int    `json:"Length" binding:"required,gt=0"`
	PacketURL               string `json:"PacketURL" binding:"required"`
	ReadLocalDownloadedFile *bool  `json:"ReadLocalDownloadedFile" binding:"required"`
}

type ReadPacket struct {
	PacketConfig
	Order binary.ByteOrder
	Eng   *gin.Engine
}

type ReadPacketResult struct {
	PacketURL          string           `json:"PacketURL"`
	PacketLength       int              `json:"PacketLength"`
	NumberOfGaps       int              `json:"NumberOfGaps"`
	NumberOfOutOfOrder int              `json:"NumberOfOutOfOrder"`
	GapIndex           []int64          `json:"GapIndex"`
	GapMap             map[int64]string `json:"GapMap"`
	OutOfOrderSeq      []int64          `json:"OutOfOrderSeq"`
}

var encoding validator.Func = func(fl validator.FieldLevel) bool {
	enc, ok := fl.Field().Interface().(string)
	if ok {
		if enc == "BigEndian" || enc == "LittleEndian" {
			return true
		}
	}
	return false
}

func NewReadPacket(encoding string, startoffset int, length int, packetUrl string) *ReadPacket {
	var packetConfig PacketConfig
	packetConfig.Encoding = encoding
	packetConfig.StartOffsetZeroIndex = startoffset
	packetConfig.Length = length
	packetConfig.PacketURL = packetUrl

	return &ReadPacket{
		PacketConfig: packetConfig,
		Eng:          gin.New(),
	}
}

func Download(url string) error {
	out, err := os.Create("./samplePcaps/download.pcap")
	if err != nil {
		return err
	}
	defer out.Close()
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	n, err := io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	log.Println("Wrote", n, "bytes")
	return nil
}

func main() {
	pkt := NewReadPacket("BigEndian", 40, 2, "https://YOUR_PCAP_URL")

	pkt.Eng.Use(gin.Logger())
	pkt.Eng.Use(gin.Recovery())
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterValidation("encoding", encoding)
	}

	pkt.Eng.GET("/config", func(c *gin.Context) {
		c.JSON(http.StatusOK, pkt.PacketConfig)
	})
	pkt.Eng.POST("/config", pkt.UploadPacketHandler)

	pkt.Eng.Run("localhost:8080")
}

func (pkt *ReadPacket) UploadPacketHandler(ctx *gin.Context) {
	var req ReadPacket
	if err := ctx.BindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// updating struct with new values
	pkt.Encoding = req.Encoding
	pkt.StartOffsetZeroIndex = req.StartOffsetZeroIndex
	pkt.Length = req.Length
	pkt.PacketURL = req.PacketURL
	pkt.ReadLocalDownloadedFile = req.ReadLocalDownloadedFile

	if !*pkt.ReadLocalDownloadedFile {
		err := Download(pkt.PacketURL)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	var resp ReadPacketResult

	handle, err = pcap.OpenOffline("./samplePcaps/download.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	switch strings.ToLower(pkt.Encoding) {
	case "bigendian":
		pkt.Order = binary.BigEndian
	case "littleendian":
		pkt.Order = binary.LittleEndian
	}

	switch pkt.Length {
	case 2:
		var data uint16
		ch := Read(data, pkt, &resp)
		GapCheck(ctx, ch, &resp)
	case 4:
		var data uint32
		ch := Read(data, pkt, &resp)
		GapCheck(ctx, ch, &resp)
	case 8:
		var data uint64
		ch := Read(data, pkt, &resp)
		GapCheck(ctx, ch, &resp)
	}
}

func GapCheck[T uIntType](ctx *gin.Context, ch chan T, resp *ReadPacketResult) {
	// fmt.Println(len, "packets read")
	var hold []int64
	var suspectedOutOfOrder []int64

	for d := range ch {
		hold = append(hold, int64(d))
	}
	resp.PacketLength = len(hold)
	resp.GapMap = make(map[int64]string)
	// fmt.Println(hold[:10])
	go PrintMemUsage()

	//checking gaps
	for i := 0; i < len(hold)-1; i++ {
		if hold[i+1]-hold[i] != 1 {
			resp.GapIndex = append(resp.GapIndex, hold[i]+1)
			resp.GapMap[hold[i]+1] = fmt.Sprintf("seq gap %d", hold[i+1]-hold[i])
			resp.NumberOfGaps++
			suspectedOutOfOrder = append(suspectedOutOfOrder, hold[i]+1)
		}
	}
	//checking out of order
	//if suspected out of order packets are not seen, then they are missing packets
	//not out of order
	// fmt.Println(resp.OutOfOrderSeq)
	for _, seq := range suspectedOutOfOrder {
		if isInSlice(seq, hold) {
			resp.OutOfOrderSeq = append(resp.OutOfOrderSeq, seq)
			resp.NumberOfOutOfOrder++
		}
	}
	ctx.JSON(http.StatusOK, resp)
}

func isInSlice(a int64, list []int64) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func Read[T uIntType](d T, p *ReadPacket, resp *ReadPacketResult) chan T {
	resp.PacketURL = p.PacketURL

	ch := make(chan T)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	go func() {
		defer close(ch)
		index := 0
		for {
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Println("Error:", err)
				continue
			}
			if packet.Metadata().Length < p.StartOffsetZeroIndex+p.Length {
				log.Println("Ignoring packet smaller than start offset + length at index", index)
				index++
				continue
			}
			packetByteSlice := packet.Data()[p.StartOffsetZeroIndex : p.StartOffsetZeroIndex+p.Length]
			if index < 10 {
				log.Println(packetByteSlice)
			}
			r := bytes.NewReader(packetByteSlice)

			if err := binary.Read(r, p.Order, &d); err != nil {
				fmt.Println("binary.Read failed:", err)
			}

			ch <- d
			index++
		}

	}()
	return ch
}

func PrintMemUsage() {
	//printing memory usage during execution
	tick := time.Tick(time.Second)
	done := make(chan bool)
	count := 0
	for {
		select {
		case <-done:
			return
		case <-tick:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
			fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
			fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
			fmt.Printf("\tNumGC = %v\n", m.NumGC)
			count++
		}
		if count == 10 {
			done <- true
		}
	}

}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
