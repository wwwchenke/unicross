package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

var exitError error = fmt.Errorf("Exit\n")

func ParseArgument(args []string) (setup bool, steps []bool, threadNum, index int, err error) {
	steps = make([]bool, 6)
	stepSet := false
	threadNum = 0
	index = 0
	if len(os.Args) > 1 {
		i := 1
		for ; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--setup":
				setup = true
			case "--index":
				if len(os.Args) < i+2 {
					fmt.Println("Invalid number for --index")
					err = exitError
					return
				}
				i++
				index, err = strconv.Atoi(args[i])
				if err != nil {
					fmt.Println("Invalid number for --index")
					err = exitError
					return
				}
				if index < 0 || index > 15 {
					fmt.Println("Invalid number for --index")
					err = exitError
					return
				}
			case "--step":
				if stepSet {
					fmt.Println("Duplicate setting on --step")
					err = exitError
					return
				}

				if len(os.Args) < i+2 {
					fmt.Println("Invalid step range for --step")
					err = exitError
					return
				}
				i++
				indexSign := strings.Index(os.Args[i], "-")
				if indexSign < 0 {
					step, _ := strconv.Atoi(os.Args[i])
					if step < 1 || step > 6 {
						fmt.Println("Invalid step range for --step")
						err = exitError
						return
					}
					steps[step-1] = true
					stepSet = true
				} else {
					start, _ := strconv.Atoi(os.Args[i][:indexSign])
					end, _ := strconv.Atoi(os.Args[i][indexSign+1:])
					if start < 1 || start > 6 || end < 1 || end > 6 || start > end {
						fmt.Println("Invalid step range for --step")
						err = exitError
						return
					}
					for n := start; n <= end; n++ {
						steps[n-1] = true
					}
					stepSet = true
				}
			case "--thread":
				if len(os.Args) < i+2 {
					fmt.Println("Invalid thread number for --thread")
					err = exitError
					return
				}
				i++
				n, _ := strconv.Atoi(os.Args[i])
				if n < 1 || n > 128 {
					fmt.Println("Invalid thread number for --thread")
					err = exitError
					return
				}
				threadNum = n
			default:
				fmt.Printf("Unrecognized argument %s\n", os.Args[i])
				return
			}
		}
	}
	if !setup && !stepSet {
		for i := 0; i < 6; i++ {
			steps[i] = true
		}
	}
	if threadNum == 0 {
		threadNum = 4
	}
	if setup && stepSet && !steps[0] {
		fmt.Println("Step 1 is not allowed to be skipped with --setup set")
		err = exitError
		return
	}

	err = nil
	return
}
