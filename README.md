# GeoInspector 

*Are you using `GeoInspector`? If so, let us know! Shoot us an email at censoredplanet@umich.edu.*

`GeoInspector` is a toolkit for measuring geoblocking or server-side blocking on the DNS, TCP, TLS, and HTTP protocols. `GeoInspector` performs specialized measurements to endpoints on these protocols to detect when access is blocked by the endpoint due to geoblocking. 

For more information, refer to [our paper](https://censoredplanet.org/publicaitons/russia-ukraine-invasion.pdf)

## Installation
Use the `Makefile` provided in the repository to build the binary for execution. 
 
## Configuration
The following flags can be provided for running measurements:
|         Flag           |          Default         |                       Function                         |                  Example                   |
| ---------------------- | ------------------------ | ------------------------------------------------------ | ------------------------------------------ |
| input-url-file        | Required                  | Input list of URLs to test                             |                                |
| asn-mmdb              | Required                  | Path to Maxmind ASN MMDB                               |                                |
| input-resolver-file   | Required if running DNS module  |  Input list of resolvers to send queries to                              |                                |
| input-conn-file       | Input list of servers to perform a TCP connection to and send data (required if not running in full mode)                    |                                      |                                            |
| output-dns-file                  | Stdout                    | DNS Output File    |                                            |
| control-dns-file                   | ""                    | DNS Control File with trusted domain,ip,asn values to include when a domain has no IPs |     |
| output-parsed-dns               | dns_parsed_output.csv                    | DNS Parsed output file |                                            |
| output-conn-file              | stdout      | Output File for writing TCP, TLS and HTTP connection responses                   |                                            |
| output-failed-conn-file               | failed_conn.csv | Output File for writing domain,ip pairs with failed tcp/tls connections, used to run traceroutes    |                       |
| module                | full                   | Module to run (can be dns, tcp or full (DNS + TCP))           |                                           |
| num-worker            | 100                   | Number of vantage points to perform measurements to at any moment                   |                                            |
| num-query-workers            | 3                        | Number of qeuries to perform to each resolver at any moment                   |                                            |
| num-redirects                   | 10                        | Number of redirects to follow for an HTTP request                |                                            |
| src-ip             |                       | Source IP address to use (will use default if unspecified) |                                            |
| ignore-local-resolvers             | False                    | Does not add local resolvers in measurements when enabled                           |                                            |                                      |

## Usage
Run `GeoInspector` with a command like:
```
./geoinspector --input-url-file input_url_file.csv --asn-mmdb asn.mmdb --input-resolver-file input_resolver_file.csv --module full
```

## Disclaimer
`GeoInspector` performs multiple measurements towards endpoints with domains in the payload. Please exercise caution when using `GeoInspector` to not place you or others at risk of service disruptions, and do not request illegal content. Please refer to [our paper](https://censoredplanet.org/publicaitons/russia-ukraine-invasion.pdf) for more information.

## Citation
If you use the `GeoInspector` tool or data, please cite the following publication:
```
@inproceedings{ramesh2023network,<br>
title = {Network Responses to Russia's Invasion of Ukraine in 2022: A Cautionary Tale for Internet Freedom},<br>
author = {Ramesh, Reethika and Sundara Raman, Ram and Virkud, Apurva and Dirksen, Alexandra and Huremagic, Armin, and Fifield, David and Rodenburg, Dirk and Hynes, Rod and Madory, Doug and Ensafi, Roya},<br>
booktitle={In USENIX Security Symposium},<br>
year={2023}
```

## Contributing
Our measurements are constantly improving to adapting to the changing Internet landscape, and we need the help of the community to improve `GeoInspector` and keep it updated! We welcome any and all contributions. Please feel free to open an Issue, Pull Request, or send us an email.

## Licensing
This repository is released under the GNU General Public License (see [`LICENSE`](LICENSE)).

## Contact
Email addresses: `censoredplanet@umich.edu`, `ramaks@umich.edu`, `reethika@umich.edu`, `ensafi@umich.edu`

## Contributors

[Ram Sundara Raman](https://github.com/ramakrishnansr)

[Apurva Virkud](https://github.com/avirkud)

[Gavin Li](https://github.com/developStorm)

[Reethika Ramesh](https://github.com/reethikar)