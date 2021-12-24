# poly1305-x64
A poly1305 implementation written in assembly. The assembly file has been written in such a way that it supports linux, macOS and windows. Currently, only a scalar implementation but it's already extremely fast. Not sure how much faster SSE or AVX2 would be unless one was processing multiple data streams.

## Results
When testing calculating the Poly1305 tag for 1 GB and 512 KB of random data I got the following on average:
<table>
<thead><tr><th>Processor</th><th>1 GB</th><th> 1 GB test GB/s</th> <th>512KB</th><th> 512KB test GB/s</th></tr></thead>
<tbody>
<tr> <td>Xeon E3-1230 v5</td> <td>0.434929 s</td> <td>2.299 GB/s</td> <td>0.000238 s</td> <td>2.052 GB/s</td></tr>
<tr> <td>Ryzen 5 3600X  </td> <td>0.302994 s</td> <td>3.300 GB/s</td> <td>0.000153 s</td> <td>3.191 GB/s</td></tr>
</tbody>
</table>