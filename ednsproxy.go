package main

import (
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/astaxie/beego/logs"
	"github.com/miekg/dns"
	"github.com/pmylund/go-cache"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var (
	dnss       = flag.String("dns", "114.114.114.114:53:udp,119.29.29.29:53:udp", "dns address, use `,` as sep")
	local      = flag.String("local", ":53", "local listen address")
	debug      = flag.Int("debug", 0, "debug level")
	encache    = flag.Bool("cache", false, "enable go-cache")
	negcache   = flag.Bool("negcache", false, "enable negcache")
	expire     = flag.Int64("expire", 60, "default cache expire seconds, -1 means use doamin ttl time")
	file       = flag.String("file", filepath.Join(path.Dir(os.Args[0]), "cache.dat"), "cached file")
	ipv6       = flag.Bool("6", true, "skip ipv6 record query AAAA")
	timeout    = flag.Int("timeout", 200, "read/write timeout in ms")
	ecsip      = flag.String("ecsip", "127.0.0.1", "ecs ip address")
	ecsnetmask = flag.Int("ecsnetmask", 32, "ecs netmask")

	clientTCP *dns.Client
	clientUDP *dns.Client

	DEBUG    int
	ENCACHE  bool
	NEGCACHE bool

	DNS [][]string

	conn *cache.Cache

	saveSig = make(chan os.Signal)
)

func toMd5(data string) string {
	m := md5.New()
	m.Write([]byte(data))
	return hex.EncodeToString(m.Sum(nil))
}

func intervalSaveCache() {
	save := func() {
		err := conn.SaveFile(*file)
		if err == nil {
			log.Printf("cache saved: %s\n", *file)
		} else {
			log.Printf("cache save failed: %s, %s\n", *file, err)
		}
	}
	go func() {
		for {
			select {
			case sig := <-saveSig:
				save()
				switch sig {
				case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
					os.Exit(0)
				case syscall.SIGHUP:
					log.Println("recv SIGHUP clear cache")
					conn.Flush()
				}
			case <-time.After(time.Second * 60):
				save()
			}
		}
	}()
}

func init() {
	flag.Parse()

	ENCACHE = *encache
	DEBUG = *debug
	NEGCACHE = *negcache

	runtime.GOMAXPROCS(runtime.NumCPU()*2 - 1)

	clientTCP = new(dns.Client)
	clientTCP.Net = "tcp"
	clientTCP.ReadTimeout = time.Duration(*timeout) * time.Millisecond
	clientTCP.WriteTimeout = time.Duration(*timeout) * time.Millisecond

	clientUDP = new(dns.Client)
	clientUDP.Net = "udp"
	clientUDP.ReadTimeout = time.Duration(*timeout) * time.Millisecond
	clientUDP.WriteTimeout = time.Duration(*timeout) * time.Millisecond

	if ENCACHE {
		conn = cache.New(time.Second*time.Duration(*expire), time.Second*60)
		conn.LoadFile(*file)
		intervalSaveCache()
	}

	for _, s := range strings.Split(*dnss, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		dns := s
		proto := "udp"
		parts := strings.Split(s, ":")
		if len(parts) > 2 {
			dns = strings.Join(parts[:2], ":")
			if parts[2] == "tcp" {
				proto = "tcp"
			}
		}
		_, err := net.ResolveTCPAddr("tcp", dns)
		if err != nil {
			log.Fatalf("wrong dns address %s\n", dns)
		}
		DNS = append(DNS, []string{dns, proto})
	}

	if len(DNS) == 0 {
		log.Fatalln("dns address must be not empty")
	}

	signal.Notify(saveSig, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
}

func main() {
	//logs module
	l := logs.NewLogger(1000)
	l.SetLogger("console", "")
	l.SetLevel(0)

	dns.HandleFunc(".", proxyServe)

	failure := make(chan error, 1)

	go func(failure chan error) {
		failure <- dns.ListenAndServe(*local, "tcp", nil)
	}(failure)

	go func(failure chan error) {
		failure <- dns.ListenAndServe(*local, "udp", nil)
	}(failure)

	log.Printf("ready for accept connection on tcp/udp %s ...\n", *local)

	fmt.Println(<-failure)
}

func proxyServe(w dns.ResponseWriter, req *dns.Msg) {
	l := logs.NewLogger(1000)
	l.SetLogger("console", "")
	l.SetLevel(0)
	var (
		key       string
		m         *dns.Msg
		err       error
		tried     bool
		data      []byte
		id        uint16
		query     []string
		questions []dns.Question
		used      string
	)

	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
		}
	}()

	if req.MsgHdr.Response == true { // supposed responses sent to us are bogus
		return
	}

	query = make([]string, len(req.Question))

	for i, q := range req.Question {
		if q.Qtype != dns.TypeAAAA || *ipv6 {
			questions = append(questions, q)
		}
		query[i] = fmt.Sprintf("(%s %s %s)", q.Name, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype])
	}

	if len(questions) == 0 {
		return
	}

	req.Question = questions

	id = req.Id

	req.Id = 0
	key = toMd5(req.String())
	l.Debug("req string %v", req.String())
	req.Id = id

	req = SetOrChangeEdns0(req, *ecsip, *ecsnetmask, l)

	if ENCACHE {
		if reply, ok := conn.Get(key); ok {
			data, _ = reply.([]byte)
		}
		if data != nil && len(data) > 0 {
			m = &dns.Msg{}
			m.Unpack(data)
			m.Id = id
			err = w.WriteMsg(m)

			l.Debug("id: %5d cache: HIT %v\n", id, query)
			goto end
		} else {
			l.Debug("id: %5d cache: MISS %v\n", id, query)
		}
	}

	for i, parts := range DNS {
		dns := parts[0]
		proto := parts[1]
		tried = i > 0
		if tried {
			l.Debug("id: %5d try: %v %s %s\n", id, query, dns, proto)
		} else {
			l.Debug("id: %5d resolve: %v %s %s\n", id, query, dns, proto)
		}

		client := clientUDP
		if proto == "tcp" {
			client = clientTCP
		}
		m, _, err = client.Exchange(req, dns)

		if err == nil && len(m.Answer) > 0 {
			used = dns
			break
		}
	}

	if err == nil {
		if tried {
			if len(m.Answer) == 0 {
				l.Debug("id: %5d failed: %v\n", id, query)
			} else {
				l.Debug("id: %5d bingo: %v %s\n", id, query, used)
			}
		}

		data, err = m.Pack()
		if err == nil {
			_, err = w.Write(data)

			l.Debug("negcache %v", NEGCACHE)
			if !NEGCACHE {
				if m.Rcode != dns.RcodeSuccess {
					l.Debug("code not sucess %v", m.Rcode)
					return
				}
			}
			if err == nil {
				if ENCACHE {
					m.Id = 0
					data, _ = m.Pack()
					ttl := 0
					if len(m.Answer) > 0 {
						ttl = int(m.Answer[0].Header().Ttl)
						if ttl < 0 {
							ttl = 0
						}
					}
					conn.Set(key, data, time.Second*time.Duration(ttl))
					m.Id = id
					l.Debug("id: %5d cache: CACHED %v TTL %v\n", id, query, ttl)
				}
			}
		}
	}

end:
	l.Debug("%v", req)
	if m != nil {
		l.Debug("%v", req)
	}
	if err != nil {
		l.Debug("id: %5d error: %v %s\n", id, query, err)
	}
}

//set or change edns client subnet
func SetOrChangeEdns0(m *dns.Msg, address string, netmask int, l *logs.BeeLogger) *dns.Msg {
	e := m.IsEdns0()
	if e == nil {
		//ecs support
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		e := new(dns.EDNS0_SUBNET)
		e.Code = dns.EDNS0SUBNET
		e.Family = 1                     // 1 for IPv4 source address, 2 for IPv6
		e.SourceNetmask = uint8(netmask) // 32 for IPV4, 128 for IPv6
		e.SourceScope = 0
		e.Address = net.ParseIP(address).To4() // for IPv4
		o.Option = append(o.Option, e)
		m.Extra = append(m.Extra, o)
		if DEBUG == 1 {
			l.Debug("ecs ip address  %v", ecsip)
			l.Debug("ecs netmask %v", ecsnetmask)
			l.Debug("dns.Question :\n %v", m.Question)
			l.Debug("dns.EDNS0_SUBNET info :\n %v", e)
			l.Debug("dns.OPT info :\n %v", o)
			l.Debug("req.Extra info :\n %v", m.Extra)
			l.Debug("req info :\n %v", m)
		}

	}
	return m

}
