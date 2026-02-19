package set3

import (
	"log"
	"math/rand/v2"
	"sync"
	"time"
)

const maxuint uint32 = 0xffffffff

func seedSearch(startInd uint32, step uint32, searchVal uint32, stopChan chan (struct{}), outChan chan (uint32), wg *sync.WaitGroup) {
	btr := NewMTRand()
	st := time.Now().UnixMicro()
	for si := startInd; si < maxuint; si += step {
		select {
		case <-stopChan:
			wg.Done()
			return
		default:
			if (si-startInd)%1000000 == 0 && startInd == 0 {
				et := time.Now().UnixMicro()
				run_ms := float64((et - st) / 1000.0)
				// st = time.Now().UnixMicro()
				// log.Printf("Took 1000000 steps: %f ms\n", run_ms)
				log.Printf("%.2f%% -- %.1f ms\n", float64(si)/float64(maxuint)*100, run_ms)
			}
			btr.initialize_state(si)
			check := btr.rand_int()
			if check == searchVal {
				log.Printf("Found Seed: %d\n", si)
				outChan <- si
				wg.Done()
				return
			}
		}

	}
}

func CrackRandSeed() {
	// we will work in milliseconds, instead of seconds, cause I'm not
	// into wasting time like the author is (also I hate vanilla ice)
	time.Sleep(time.Duration(rand.IntN(500)) * time.Millisecond)
	seed := uint32(time.Now().UnixMilli())
	// seed = 50000
	mtr := NewMTRand()
	mtr.initialize_state(seed)
	time.Sleep(time.Duration(rand.IntN(500)) * time.Millisecond)
	first_rand := mtr.rand_int()
	stop := make(chan (struct{}))
	output := make(chan (uint32))
	wg := sync.WaitGroup{}
	num_workers := 12
	for si := range num_workers {
		go seedSearch(uint32(si), uint32(num_workers), first_rand, stop, output, &wg)
		wg.Add(1)
	}
	found_seed := <-output
	close(stop)
	wg.Wait()
	log.Printf("Got Seed: %d\n", found_seed)
}
