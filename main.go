package main

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"log"

	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type domain struct {
	name    string
	primary string
	secret  string
	algo    string
	keyname string
}

// boiler
type F struct {
	f  *os.File
	gf *gzip.Writer
	fw *bufio.Writer
}

var config map[string]string = map[string]string{
	"wbuf": "30720", //30MB
	"dir":  "",
}
var soaResult map[string]int = map[string]int{
	"se.": 0,
	"nu.": 0,
	"li.": 0,
	"ch.": 0,
}
var domains = []domain{
	//{"ch.", "zonedata.switch.ch:53", "stZwEGApYumtXkh73qMLPqfbIDozWKZLkqRvcjKSpRnsor6A6MxixRL6C2HeSVBQNfMW4wer+qjS0ZSfiWiJ3Q==", "hmac-sha512", "tsig-zonedata-ch-public-21-01."},
	//{"li.", "zonedata.switch.ch:53", "t8GgeCn+fhPaj+cRy1epox2Vj4hZ45ax6v3rQCkkfIQNg5fsxuU23QM5mzz+BxJ4kgF/jiQyBDBvL+XWPE6oCQ==", "hmac-sha512", "tsig-zonedata-li-public-21-01."},
	{"se.", "zonedata.iis.se:53", "", "", ""},
	{"nu.", "zonedata.iis.se:53", "", "", ""},
}

// boiler (filename, buffsize)
func CreateGZ(s string, b int) (f F) {

	fi, err := os.OpenFile(s, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Printf("Error in Create\n")
		panic(err)
	}
	gf, _ := gzip.NewWriterLevel(fi, flate.BestCompression)
	fw := bufio.NewWriterSize(gf, b)
	f = F{fi, gf, fw}
	return
}

// boiler
func WriteGZ(f F, s string) {
	(f.fw).WriteString(s)
}

// boiler
func CloseGZ(f F) {
	(f.fw).Flush()
	(f.gf).Close()
	(f.f).Close()
}

func xfr(d domain) {
	sCount := 0
	// prep file and buffers
	b, _ := strconv.Atoi(config["wbuf"])
	l := strings.TrimRight(d.name, ".")
	f := CreateGZ(config["dir"]+l+".zone", b)
	data := []string{}

	// prep DNS message

	t := new(dns.Transfer)
	m := new(dns.Msg)
	fmt.Println("Name: ", d.name)
	fmt.Println("Secret: ", d.secret)
	fmt.Println("Algo: ", d.algo)
	fmt.Println("Keyname: ", d.keyname)
	m.SetAxfr(d.name)

	if d.secret != "" {
		t.TsigSecret = map[string]string{d.keyname: d.secret}
		switch d.algo {
		case "hmac-sha1":
			m.SetTsig(d.keyname, dns.HmacSHA1, 300, time.Now().Unix())
		case "hmac-sha256":
			m.SetTsig(d.keyname, dns.HmacSHA256, 300, time.Now().Unix())
		case "hmac-sha512":
			m.SetTsig(d.keyname, dns.HmacSHA512, 300, time.Now().Unix())
		default:
			m.SetTsig(d.keyname, dns.HmacSHA512, 300, time.Now().Unix())
		}

	}
	// Send DNS message
	c, err := t.In(m, d.primary)
	if err != nil {
		fmt.Println(err)
		return
	}
	// process response
	for r := range c {
		if r.Error != nil {
			fmt.Println(l, " |", r.Error)
		}
		for _, a := range r.RR {
			switch a.(type) {
			case *dns.NS:
				WriteGZ(f, a.String()+"\n")
			case *dns.SOA:
				WriteGZ(f, a.String()+"\n")
				sCount += 1
			case *dns.DS:
				WriteGZ(f, a.String()+"\n")
			default:
				continue
			}
		}
	}
	if len(data) > 0 {
		for _, r := range data {
			WriteGZ(f, r+"\n")
		}
	}
	CloseGZ(f)
	soaResult[d.name] = sCount
}
func main() {
	for _, do := range domains {
		e := os.Remove(do.name + "zone")
		if e != nil {
			if os.IsNotExist(e) {
				continue
			} else {
				log.Fatal(e)
			}
		}
	}
	wg := sync.WaitGroup{}
	for i, d := range domains {
		wg.Add(1)
		go func(i int, d domain) {
			defer wg.Done()
			xfr(d)
		}(i, d)
	}
	wg.Wait()
	fmt.Println(soaResult)
}
