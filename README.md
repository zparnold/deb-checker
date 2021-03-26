# Deb Checker
Checks a return delimited list of CVE's for whether or not they are still vulnerable in a base debian distro

# Usage
```
./deb-checker -n file.txt -d stretch
```

* `-n` the name of the text file with a return delimited list of `CVE-`'s to check
* `-d` the name of the distro (stretch, jessie, buster)

## Example file contents
`cat file.txt`:
```
CVE-2016-5131
CVE-2019-3844
CVE-2019-1010023
CVE-2013-4235
CVE-2017-3142
```