![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)


# PTVULNSEARCHER
> Common Vulnerabilities and Exposures Searcher

ptvulnsearcher is a tool for searching CVE (Common Vulnerabilities and Exposures). This tool allows searching using keywords or exact CVE.

## Installation

```
pip install ptvulnsearcher
```

### Add to PATH
If you cannot invoke the script in your terminal, its probably because its not in your PATH. Fix it by running commands below.
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

## Usage examples

```
ptvulnsearcher -s "Apache Tomcat"             # Search CVE for the specified string
ptvulnsearcher -cve CVE-2022-29885            # Search specified CVE
```

## Options
```
   -cve  --cve              <CVE ID>           Search based on CVE ID
   -vn   --vendor_name      <vendor_name>      Search based on vendor name
   -pn   --product_name     <product_name>     Search based on product name
   -pv   --product_version  <product_version>  Search based on product version
   -j    --json                                Output in JSON format
   -v    --version                             Show script version and exit
   -h    --help                                Show this help message and exit
```

## Dependencies
- requests
- ptlibs

We use [ExifTool](https://exiftool.org/) to extract metadata.
Python 3.6+ is required.

## Version History
* 0.0.1
    * Alpha releases

## License

Copyright (c) 2022 HACKER Consulting s.r.o.

ptinsearcher is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ptinsearcher is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ptinsearcher.  If not, see <https://www.gnu.org/licenses/>.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!
