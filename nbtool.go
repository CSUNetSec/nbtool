package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"io"
	pb "nbtool/netbrane-shared/capture/flow-records"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
)

type nbFlowRecordIndex struct {
	recordnum uint32
	offset    uint64
}

type ReadSeekCloser interface {
	io.Reader
	io.Writer
	io.Seeker
}

type recrange struct {
	start, end int
}

type recranges []recrange
type filerecranges []recranges

type workercommand struct {
	outfile   string
	outdir    string
	infile    string
	indexfile string
	outtype   string
	ranges    recranges
}

func (r recranges) inranges(i int) bool {
	for _, ran := range r {
		if i >= ran.start && i <= ran.end {
			return true
		}
	}
	return false
}

//dummy implementation of String for flag.Value interface
func (f *filerecranges) String() string {
	return ""
}

func (f *filerecranges) Set(val string) error {
	perfiles := strings.Split(val, ":")
	for _, frange := range perfiles {
		ran := new(recranges)
		ranges := strings.Split(frange, ",")
		for _, r := range ranges {
			minmax := strings.Split(r, "-")
			switch len(minmax) {
			case 1:
				num, err := strconv.Atoi(minmax[0])
				if err != nil {
					return err
				}
				*ran = append(*ran, recrange{start: num, end: num})
			case 2:
				num1, err1 := strconv.Atoi(minmax[0])
				num2, err2 := strconv.Atoi(minmax[1])
				if err1 != nil || err2 != nil {
					return errors.New(fmt.Sprintf("error: %s,%s", err1, err2))
				}
				*ran = append(*ran, recrange{start: num1, end: num2})
			default:
				return errors.New("ranges have to be either single numbers or in the form number1-number2")
			}
		}
		*f = append(*f, *ran)
	}
	return nil
}
func splitNbFlowRecord(data []byte, atEOF bool) (advance int, token []byte, err error) {
	buf := bytes.NewBuffer(data)
	pbsize := uint32(0)
	if cap(data) < 4 || len(data) < 4 {
		return 0, nil, nil
	}
	binary.Read(buf, binary.BigEndian, &pbsize)
	if cap(data) < int(pbsize+4) || len(data) < int(pbsize+4) {
		return 0, nil, nil
	}
	return int(4 + pbsize), data[4 : pbsize+4], nil

}

func (n *nbFlowRecordIndex) String() string {
	return fmt.Sprintf("%d\t%d", n.recordnum, n.offset)
}

//accepts an error (can be nil which turns the func into a noop
//and variadic arguemnts that are fds to be closed before calling
//os.exit in case the error is not nil
func errx(e error, fds ...io.Closer) {
	if e == nil {
		return
	}
	fmt.Printf("error: %s\n", e)
	for _, fd := range fds {
		fd.Close()
	}
	os.Exit(-1)
}

func suffixFieldsFunc(c rune) bool {
	if c == '.' {
		return true
	}
	return false
}

func dirFieldsFunc(c rune) bool {
	if c == '/' {
		return true
	}
	return false
}

//chech that fname has a suffix that is one of the variadic string arguments.
func checkSuffix(fname string, sufs ...string) (string, error) {
	strarr := strings.FieldsFunc(fname, suffixFieldsFunc)
	if len(strarr) < 2 {
		return "", errors.New("no suffix detected.")
	}
	for _, suf := range sufs {
		if strarr[1] == suf {
			return suf, nil
		}
	}
	return "", errors.New("suffix of filename is not  in " + fmt.Sprintf("%v", sufs))
}

func getFnameNoSuffix(fname string) string {
	ind := strings.LastIndex(fname, "/")
	fnameparts := strings.FieldsFunc(fname[ind:], suffixFieldsFunc)
	return fnameparts[0]
}

func getDir(fname string) string {
	//fnameparts := strings.FieldsFunc(fname, dirFieldsFunc)
	ind := strings.LastIndex(fname, "/")
	return fname[:ind]
}

func fileExists(fname string) bool {
	if _, err := os.Stat(fname); os.IsNotExist(err) {
		return false
	}
	return true
}

func usage() string {
	return `usage:
	` + os.Args[0] + ` [flags] command filename... 
	command can be one of [unzip, extract, count]
	filenames must be .nb netbrane flowspec files or .unb unzipped flowspec files`
}

func count(cmd workercommand) {
	var (
		indesc       *os.File
		err          error
		numentries   uint32
		lastindexrec nbFlowRecordIndex
		i            int
	)
	isv2 := false
	fname := cmd.infile
	_, err = checkSuffix(fname, "unb")
	errx(err)
	_, err = os.Stat(fname)
	errx(err)
	indesc, err = os.Open(fname)
	errx(err)
	defer indesc.Close()
	errx(err)
	fi, err := os.Stat(fname)
	errx(err)
	flen := fi.Size()
	if flen < 4 {
		errx(errors.New("file length too small"))
	}
	//seeking to flen-4 to get number of entries if it's v2
	indesc.Seek(flen-4, 0) //0 is io.SeekStart
	binary.Read(indesc, binary.BigEndian, &numentries)
	if isnbversion2(numentries, uint64(flen)) {
		isv2 = true
		indexlast := flen - (4 + 12) //last entry, get number and seek from there till the end of file
		indesc.Seek(indexlast, 0)    //0 is io.SeekStart
		binary.Read(indesc, binary.BigEndian, &lastindexrec)
		indesc.Seek(int64(lastindexrec.offset), 0) //seek to last recorded offset
		i = int(lastindexrec.recordnum)            //start from record num that we got from index
		bufindesc := bufio.NewReader(indesc)
		nbscanner := bufio.NewScanner(bufindesc)
		scanbuffer := make([]byte, 2<<26) //an internal buffer for the large tokens (67M)
		nbscanner.Buffer(scanbuffer, cap(scanbuffer))
		nbscanner.Split(splitNbFlowRecord)
		for nbscanner.Scan() {
			i++
		}
	} else {
		indesc.Seek(0, 0)
		bufindesc := bufio.NewReader(indesc)
		nbscanner := bufio.NewScanner(bufindesc)
		scanbuffer := make([]byte, 2<<26) //an internal buffer for the large tokens (67M)
		nbscanner.Buffer(scanbuffer, cap(scanbuffer))
		nbscanner.Split(splitNbFlowRecord)
		i = 0
		for nbscanner.Scan() {
			i++
		}
	}
	fmt.Printf("File:%s [v2:%v] has :%d entries\n", fname, isv2, i)

}

func unzip(cmd workercommand) {
	var (
		err     error
		fname   string
		outdirf string
	)
	fname = cmd.infile
	_, err = checkSuffix(fname, "nb")
	errx(err)
	_, err = os.Stat(fname)
	errx(err)
	indesc, err := os.Open(fname)
	defer indesc.Close()
	errx(err)
	if cmd.outdir == "" {
		outdirf = getDir(fname) + getFnameNoSuffix(fname) + "-extracted"
	} else {
		outdirf = cmd.outdir
	}
	if fileExists(outdirf) {
		//errx(errors.New("destination directory exists"), indesc)
		fmt.Println("warning: output dir " + outdirf + " already exists")
	} else {
		err = os.Mkdir(outdirf, 0711)
		errx(err, indesc)
	}
	outf := outdirf + getFnameNoSuffix(fname) + "." + cmd.outtype
	if fileExists(outf) {
		errx(errors.New("output file already exists"), indesc)
	}
	zreader, err := zlib.NewReader(indesc)
	errx(err, indesc)
	outdesc, err := os.Create(outf)
	defer outdesc.Close()
	errx(err, indesc)
	nb, err := io.Copy(outdesc, zreader)
	errx(err, indesc, outdesc)
	fmt.Printf("wrote %d bytes to %s\n", nb, outf)
	return
}

func isnbversion2(num uint32, flen uint64) bool {
	if flen < 12*uint64(num)+4 {
		return false
	}
	return true
}

func genworkers(num int, f func(workercommand), wg *sync.WaitGroup) []chan workercommand {
	ret := make([]chan workercommand, num)
	for i := 0; i < num; i++ {
		ret[i] = make(chan workercommand)
		go func(cc <-chan workercommand, i int) {
			//fmt.Printf("starting worker %d\n", i)
			for {
				select {
				case cmd, ok := <-cc:
					if !ok {
						cc = nil
					} else {
						f(cmd)
					}
				}
				if cc == nil {
					//fmt.Printf("terminating worker %d\n", i)
					break
				}
			}
			wg.Done()
		}(ret[i], i)
	}
	return ret
}

func extract(cmd workercommand) {
	var (
		err        error
		numentries uint32
		flowindex  nbFlowRecordIndex
		jm         jsonpb.Marshaler
		outdirf    string
		indesc     *os.File
	)
	fname := cmd.infile
	_, err = checkSuffix(fname, "unb")
	errx(err)
	fi, err := os.Stat(fname)
	errx(err)
	flen := fi.Size()
	if flen < 4 {
		errx(errors.New("file length too small"))
	}
	indesc, err = os.Open(fname)
	errx(err)
	defer indesc.Close()
	errx(err)
	if cmd.outdir == "" {
		outdirf = getDir(fname) + getFnameNoSuffix(fname) + "-extracted"
	} else {
		outdirf = cmd.outdir
	}
	if fileExists(outdirf) {
		//errx(errors.New("destination directory exists"), indesc)
		fmt.Println("warning: output dir " + outdirf + " already exists")
	} else {
		err = os.Mkdir(outdirf, 0711)
		errx(err, indesc)
	}

	outf := outdirf + getFnameNoSuffix(fname) + "." + cmd.outtype
	outdesc, err := os.Create(outf)
	defer outdesc.Close()
	errx(err, indesc)
	jsonout := false
	if cmd.outtype == "json" {
		jsonout = true
	}
	//seeking to flen-4 to get number of entries if it's v2
	indesc.Seek(flen-4, 0) //0 is io.SeekStart
	binary.Read(indesc, binary.BigEndian, &numentries)
	if isnbversion2(numentries, uint64(flen)) {
		indexf := outdirf + "INDEX"
		indexdesc, err := os.Create(indexf)
		defer indexdesc.Close()
		errx(err, indesc, outdesc)
		indexstart := flen - (12*int64(numentries) + 4)
		indesc.Seek(indexstart, 0) //0 is io.SeekStart
		for i := uint32(0); i < numentries; i++ {
			binary.Read(indesc, binary.BigEndian, &flowindex)
			fmt.Fprintf(indexdesc, "%s\n", flowindex)
		}
	} else {
		indesc.Seek(0, 0)
		bufindesc := bufio.NewReader(indesc)
		nbscanner := bufio.NewScanner(bufindesc)
		scanbuffer := make([]byte, 2<<26) //an internal buffer for the large tokens (67M)
		nbscanner.Buffer(scanbuffer, cap(scanbuffer))
		nbscanner.Split(splitNbFlowRecord)
		i := 0
		totsz := 0
		record := pb.CaptureRecordUnion{}
		for nbscanner.Scan() {
			i++
			if cmd.ranges == nil || !cmd.ranges.inranges(i) { // ranges are not in the command, or not in range
				continue
			}
			sz := len(nbscanner.Bytes())
			totsz += sz
			if jsonout == true {
				err := proto.Unmarshal(nbscanner.Bytes(), &record)
				if err != nil {
					fmt.Printf("bytes->pb error:%s\n", err)
				} else {
					str, err := jm.MarshalToString(&record)
					if err != nil {
						fmt.Printf("pb->json error:%s\n", err)
					} else {
						fmt.Fprintf(outdesc, "%s\n", str)
					}
				}
			} else {
				errlen := binary.Write(outdesc, binary.BigEndian, len(nbscanner.Bytes())) //writing the length in big endian
				errbytes := binary.Write(outdesc, binary.BigEndian, nbscanner.Bytes())    //writing the data in big endian
				if err != nil || errbytes != nil {
					fmt.Printf("write pb len error:%s\nwrite pb error:%s", errlen, errbytes)
				}
			}

		}
		fmt.Printf("this file has %d entries of total size:%d\n", i, totsz)
	}
}

var (
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	outfile    = flag.String("outfile", "", "write output of command to file")
	outdir     = flag.String("outdir", "", "write output of command to file")
	outformat  = flag.String("outformat", "json", "write output of command to file")
	workers    = flag.Int("workers", 10, "number of workers")
	//record ranges required for extraction that are applied in that order to file arguments
	franges   filerecranges
	workrchan []chan workercommand
)

func init() {
	flag.Var(&franges, "ranges", "column(:) seperated list of comma(,) separated ranges (2-3), or numbers (12) that are applied to consecutive files")
	flag.Parse()
}

func main() {
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		errx(err)
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	if *outformat != "json" && *outformat != "pb" {
		errx(errors.New("output formats can be either json or pb"))
	}
	//fmt.Printf("ranges:%+v\n", franges)
	if len(flag.Args()) < 2 {
		fmt.Printf("%s \nflags are:\n", usage())
		flag.PrintDefaults()
		errx(errors.New("malformed command"))
	}
	if len(franges) > len(flag.Args()[1:]) {
		errx(errors.New("can't have more ranges than files"))
	}
	wg := sync.WaitGroup{}
	wg.Add(*workers)
	switch flag.Arg(0) {
	case "unzip":
		*outformat = "unb"
		workrchan = genworkers(*workers, unzip, &wg)
		for i, fname := range flag.Args()[1:] {
			workrchan[i%*workers] <- workercommand{infile: fname, outtype: *outformat, outdir: *outdir}
		}
	case "extract":
		workrchan = genworkers(*workers, extract, &wg)
		for i, fname := range flag.Args()[1:] {
			workrchan[i%*workers] <- workercommand{infile: fname, outtype: *outformat, outdir: *outdir}
			if i < len(franges) {
				workrchan[i%*workers] <- workercommand{infile: fname, outtype: *outformat, outdir: *outdir, ranges: franges[i]}
			} else {
				workrchan[i%*workers] <- workercommand{infile: fname, outtype: *outformat, outdir: *outdir}
			}
		}
	case "count":
		workrchan = genworkers(*workers, count, &wg)
		for i, fname := range flag.Args()[1:] {
			workrchan[i%*workers] <- workercommand{infile: fname}
		}
	default:
		fmt.Printf("%s \nflags are:\n", usage())
		flag.PrintDefaults()
		goto EXIT
	}
	for _, c := range workrchan {
		close(c)
	}
	wg.Wait()
EXIT:
	return
}