# benchmark-tokens

## Results

- MBA

### Sign [ms/op]

| alg             | 10    | 100   | 1000  | 1000  | 10000  |
| --------------- | ----- | ----- | ----- | ----- | ------ |
| Paseto V2       | 0.059 | 0.060 | 0.078 | 0.207 | 1.435  |
| ES512           | 6.479 | 6.718 | 6.502 | 6.960 | 7.972  |
| ES384           | 3.954 | 3.586 | 3.867 | 3.665 | 5.989  |
| ES256           | 0.033 | 0.035 | 0.045 | 0.157 | 1.242  |
| RS512(4096bits) | 8.721 | 9.203 | 8.815 | 8.997 | 10.286 |
| RS384(4096bits) | 8.697 | 8.760 | 8.837 | 9.060 | 10.104 |
| RS256(4096bits) | 9.626 | 8.973 | 8.898 | 9.034 | 10.245 |
| RS512(2048bits) | 1.552 | 1.656 | 1.507 | 1.646 | 2.733  |
| RS384(2048bits) | 1.547 | 1.558 | 1.671 | 1.674 | 2.741  |
| RS256(2048bits) | 1.626 | 1.708 | 1.600 | 1.826 | 3.153  |

### Verify [ms/op]

| alg             | 10    | 100   | 1000  | 1000  | 10000 |
| --------------- | ----- | ----- | ----- | ----- | ----- |
| Paseto V2       | 0.162 | 0.157 | 0.167 | 0.318 | 1.746 |
| ES512           | 0.003 | 0.004 | 0.004 | 0.004 | 0.003 |
| ES384           | 0.003 | 0.003 | 0.003 | 0.003 | 0.003 |
| ES256           | 0.003 | 0.003 | 0.003 | 0.003 | 0.003 |
| RS512(4096bits) | 0.003 | 0.003 | 0.003 | 0.003 | 0.003 |
| RS384(4096bits) | 0.003 | 0.003 | 0.003 | 0.003 | 0.003 |
| RS256(4096bits) | 0.003 | 0.003 | 0.003 | 0.003 | 0.003 |
| RS512(2048bits) | 0.003 | 0.003 | 0.003 | 0.003 | 0.003 |
| RS384(2048bits) | 0.003 | 0.003 | 0.003 | 0.003 | 0.003 |
| RS256(2048bits) | 0.003 | 0.003 | 0.004 | 0.004 | 0.004 |

## Benchmark

```bash
$ make benchmark
goos: darwin
goarch: amd64
pkg: github.com/kzmake/benchmark-tokens
Benchmark_JWT_ES256_Sign/len10-8                   34052             33669 ns/op            7484 B/op         63 allocs/op
Benchmark_JWT_ES256_Sign/len100-8                  34266             35082 ns/op            7949 B/op         64 allocs/op
Benchmark_JWT_ES256_Sign/len1000-8                 26030             45801 ns/op           11047 B/op         64 allocs/op
Benchmark_JWT_ES256_Sign/len10000-8                 7185            157306 ns/op           41608 B/op         64 allocs/op
Benchmark_JWT_ES256_Sign/len100000-8                 986           1242701 ns/op          369606 B/op         66 allocs/op
Benchmark_JWT_ES256_Verify/len10-8                348842              3274 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES256_Verify/len100-8               334597              3299 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES256_Verify/len1000-8              347773              3583 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES256_Verify/len10000-8             318222              3483 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES256_Verify/len100000-8            348097              3515 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES384_Sign/len10-8                     318           3954124 ns/op         1751988 B/op      14445 allocs/op
Benchmark_JWT_ES384_Sign/len100-8                    325           3586690 ns/op         1752490 B/op      14446 allocs/op
Benchmark_JWT_ES384_Sign/len1000-8                   316           3867642 ns/op         1758288 B/op      14467 allocs/op
Benchmark_JWT_ES384_Sign/len10000-8                  314           3665846 ns/op         1789361 B/op      14460 allocs/op
Benchmark_JWT_ES384_Sign/len100000-8                 249           5989426 ns/op         2152287 B/op      14483 allocs/op
Benchmark_JWT_ES384_Verify/len10-8                300925              3815 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES384_Verify/len100-8               319004              3738 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES384_Verify/len1000-8              288447              3821 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES384_Verify/len10000-8             331278              3832 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES384_Verify/len100000-8            312376              3658 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES512_Sign/len10-8                     188           6479786 ns/op         3033837 B/op      19602 allocs/op
Benchmark_JWT_ES512_Sign/len100-8                    172           6718850 ns/op         3036572 B/op      19617 allocs/op
Benchmark_JWT_ES512_Sign/len1000-8                   181           6502819 ns/op         3047566 B/op      19663 allocs/op
Benchmark_JWT_ES512_Sign/len10000-8                  169           6960166 ns/op         3079342 B/op      19654 allocs/op
Benchmark_JWT_ES512_Sign/len100000-8                 147           7972722 ns/op         3445802 B/op      19626 allocs/op
Benchmark_JWT_ES512_Verify/len10-8                292252              3936 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES512_Verify/len100-8               328051              4218 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES512_Verify/len1000-8              274686              4032 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES512_Verify/len10000-8             272065              4125 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_ES512_Verify/len100000-8            298764              3980 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS256_2048bits_Sign/len10-8                    730           1626370 ns/op           35569 B/op        135 allocs/op
Benchmark_JWT_RS256_2048bits_Sign/len100-8                   733           1708083 ns/op           36056 B/op        136 allocs/op
Benchmark_JWT_RS256_2048bits_Sign/len1000-8                  733           1600188 ns/op           39140 B/op        136 allocs/op
Benchmark_JWT_RS256_2048bits_Sign/len10000-8                 697           1826426 ns/op           70411 B/op        137 allocs/op
Benchmark_JWT_RS256_2048bits_Sign/len100000-8                370           3153764 ns/op          410662 B/op        139 allocs/op
Benchmark_JWT_RS256_2048bits_Verify/len10-8               322675              3915 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS256_2048bits_Verify/len100-8              266088              3844 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS256_2048bits_Verify/len1000-8             293973              4203 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS256_2048bits_Verify/len10000-8            292395              4721 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS256_2048bits_Verify/len100000-8           277665              4622 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS256_4096bits_Sign/len10-8                    128           9626516 ns/op           81877 B/op        150 allocs/op
Benchmark_JWT_RS256_4096bits_Sign/len100-8                   132           8973025 ns/op           82284 B/op        150 allocs/op
Benchmark_JWT_RS256_4096bits_Sign/len1000-8                  132           8898624 ns/op           85581 B/op        151 allocs/op
Benchmark_JWT_RS256_4096bits_Sign/len10000-8                 127           9034070 ns/op          116193 B/op        151 allocs/op
Benchmark_JWT_RS256_4096bits_Sign/len100000-8                100          10245599 ns/op          457874 B/op        153 allocs/op
Benchmark_JWT_RS256_4096bits_Verify/len10-8               324937              3752 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS256_4096bits_Verify/len100-8              304756              3846 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS256_4096bits_Verify/len1000-8             295520              3809 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS256_4096bits_Verify/len10000-8            263286              3931 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS256_4096bits_Verify/len100000-8           263486              3833 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS384_2048bits_Sign/len10-8                    786           1547755 ns/op           35674 B/op        135 allocs/op
Benchmark_JWT_RS384_2048bits_Sign/len100-8                   673           1558319 ns/op           36157 B/op        136 allocs/op
Benchmark_JWT_RS384_2048bits_Sign/len1000-8                  703           1671349 ns/op           39239 B/op        136 allocs/op
Benchmark_JWT_RS384_2048bits_Sign/len10000-8                 687           1674462 ns/op           70252 B/op        136 allocs/op
Benchmark_JWT_RS384_2048bits_Sign/len100000-8                430           2741174 ns/op          407818 B/op        139 allocs/op
Benchmark_JWT_RS384_2048bits_Verify/len10-8               292746              3879 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS384_2048bits_Verify/len100-8              301706              3859 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS384_2048bits_Verify/len1000-8             308943              3852 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS384_2048bits_Verify/len10000-8            260246              3886 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS384_2048bits_Verify/len100000-8           276907              3897 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS384_4096bits_Sign/len10-8                    132           8697072 ns/op           81905 B/op        149 allocs/op
Benchmark_JWT_RS384_4096bits_Sign/len100-8                   133           8760709 ns/op           82379 B/op        150 allocs/op
Benchmark_JWT_RS384_4096bits_Sign/len1000-8                  132           8837514 ns/op           85623 B/op        151 allocs/op
Benchmark_JWT_RS384_4096bits_Sign/len10000-8                 134           9060814 ns/op          116747 B/op        151 allocs/op
Benchmark_JWT_RS384_4096bits_Sign/len100000-8                100          10104202 ns/op          469790 B/op        154 allocs/op
Benchmark_JWT_RS384_4096bits_Verify/len10-8               347389              3729 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS384_4096bits_Verify/len100-8              289454              3815 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS384_4096bits_Verify/len1000-8             329343              3776 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS384_4096bits_Verify/len10000-8            288356              3791 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS384_4096bits_Verify/len100000-8           310920              3817 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS512_2048bits_Sign/len10-8                    763           1552387 ns/op           35707 B/op        135 allocs/op
Benchmark_JWT_RS512_2048bits_Sign/len100-8                   675           1656451 ns/op           36168 B/op        136 allocs/op
Benchmark_JWT_RS512_2048bits_Sign/len1000-8                  741           1507871 ns/op           39259 B/op        136 allocs/op
Benchmark_JWT_RS512_2048bits_Sign/len10000-8                 711           1646163 ns/op           70333 B/op        136 allocs/op
Benchmark_JWT_RS512_2048bits_Sign/len100000-8                423           2733266 ns/op          407922 B/op        139 allocs/op
Benchmark_JWT_RS512_2048bits_Verify/len10-8               325885              3744 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS512_2048bits_Verify/len100-8              280830              3824 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS512_2048bits_Verify/len1000-8             293482              3828 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS512_2048bits_Verify/len10000-8            308563              3745 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS512_2048bits_Verify/len100000-8           295087              3814 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS512_4096bits_Sign/len10-8                    136           8721655 ns/op           81883 B/op        149 allocs/op
Benchmark_JWT_RS512_4096bits_Sign/len100-8                   133           9203331 ns/op           82421 B/op        151 allocs/op
Benchmark_JWT_RS512_4096bits_Sign/len1000-8                  134           8815098 ns/op           85747 B/op        151 allocs/op
Benchmark_JWT_RS512_4096bits_Sign/len10000-8                 130           8997044 ns/op          116798 B/op        151 allocs/op
Benchmark_JWT_RS512_4096bits_Sign/len100000-8                120          10286676 ns/op          460735 B/op        154 allocs/op
Benchmark_JWT_RS512_4096bits_Verify/len10-8               334628              3725 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS512_4096bits_Verify/len100-8              300462              3755 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS512_4096bits_Verify/len1000-8             293882              3738 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS512_4096bits_Verify/len10000-8            317971              3766 ns/op            1256 B/op         11 allocs/op
Benchmark_JWT_RS512_4096bits_Verify/len100000-8           302996              3975 ns/op            1256 B/op         11 allocs/op
Benchmark_Paseto_V2_Sign/len10-8                           18950             59948 ns/op            1504 B/op         30 allocs/op
Benchmark_Paseto_V2_Sign/len100-8                          19659             60506 ns/op            2417 B/op         31 allocs/op
Benchmark_Paseto_V2_Sign/len1000-8                         15634             78020 ns/op           10889 B/op         31 allocs/op
Benchmark_Paseto_V2_Sign/len10000-8                         5144            207606 ns/op           72614 B/op         30 allocs/op
Benchmark_Paseto_V2_Sign/len100000-8                         747           1435024 ns/op          747525 B/op         31 allocs/op
Benchmark_Paseto_V2_Verify/len10-8                          7989            162547 ns/op            1176 B/op         26 allocs/op
Benchmark_Paseto_V2_Verify/len100-8                         7498            157034 ns/op            1720 B/op         28 allocs/op
Benchmark_Paseto_V2_Verify/len1000-8                        6920            167037 ns/op            5832 B/op         28 allocs/op
Benchmark_Paseto_V2_Verify/len10000-8                       3597            318093 ns/op           45256 B/op         28 allocs/op
Benchmark_Paseto_V2_Verify/len100000-8                       668           1746131 ns/op          459725 B/op         28 allocs/op
```
