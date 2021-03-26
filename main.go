package main

import (
	"flag"
	"fmt"
	"github.com/gocolly/colly/v2"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	c := colly.NewCollector()
	fName := flag.String("n", "", "-n something.txt, the filepath of return delimited CVE's")
	dName := flag.String("d", "", "-d buster, the debian distro version name you are targeting")
	flag.Parse()

	if *fName == "" || *dName == "" {
		fmt.Println("You must set both -n and -d flags before running")
		os.Exit(-1)
	}

	b, err := ioutil.ReadFile(*fName)
	if err != nil {
		fmt.Println("Unable to open CVE file for reading: ", err)
		os.Exit(-1)
	}
	cveCollection := strings.Split(string(b), "\n")
	for _, cve := range cveCollection {
		vuln := Vulnerability{}
		//Package info
		c.OnHTML("body > table:nth-child(5)", func(e *colly.HTMLElement) {
			e.ForEach("tr", func(i int, row *colly.HTMLElement) {
				//The first row has packages and affected versions
				if i == 1 {
					vuln.PackageName = strings.TrimSuffix(row.DOM.Find("td:nth-child(1)").Text(), " (PTS)")
				}
				if strings.Contains(row.DOM.Find("td:nth-child(2)").Text(), *dName) {
					vuln.PackageVersion = row.DOM.Find("td:nth-child(3)").Text()
					vuln.Status = row.DOM.Find("td:nth-child(4)").Text()
				}
			})
		})

		c.Visit(fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", cve))
		if vuln.Status != "" {
			fmt.Println(fmt.Sprintf("Source package %s (version %s) is %s (%s) in %s", vuln.PackageName, vuln.PackageVersion, vuln.Status, cve, *dName))
		}
	}
}

type Vulnerability struct {
	PackageName    string
	PackageVersion string
	Status         string
}
