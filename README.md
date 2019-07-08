![Supported Python versions](https://img.shields.io/badge/python-3.6-blue.svg?style=flat-square)

# **Airopy - Wireless Packet Capture**

Get clients and access points. With Alfa cards this script works correctly.

## Dependencies

To run this script first install requirements as follows:

```[python]
sudo pip3 install requirements.txt 
```

## How to use

In the examples I don't add 'sudo', but to execute them you need high privileges.

To get help:
```[python]
python3 airopy.py -h
```

To get APS:

```[python]
python3 airopy.py -i wlx00c0ca81fb80 --aps
```

To get Stations:
```[python]
python3 airopy.py -i wlx00c0ca81fb80 --stations
```

To get APS and Stations:
```[python]
python3 airopy.py -i wlx00c0ca81fb80 --aps --stations
```

To filter by a particular vendor:
```[python]
python3 airopy.py -i wlx00c0ca81fb80 --stations -d 0
```

To filter mac vendors, please check the number in mac_vendors.py. This last option can return unwanted devices, as it is based on the following unvalidated prefixes on my part:

* [aallan](https://gist.github.com/aallan/b4bb86db86079509e6159810ae9bd3e4)
* [WiFiBroot](https://raw.githubusercontent.com/hash3liZer/WiFiBroot/master/utils/macers.txt)

If you use it in America, add --america.


## Author

Josué Encinar

[![twitter][1.1]][1]


## This project has been based on

[Wifijammer from Dan McInerney](https://github.com/DanMcInerney/wifijammer)

## License

Copyright (c) 2014, Dan McInerney All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of Dan McInerney nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


 
[1.1]: http://i.imgur.com/tXSoThF.png (twitter icon with padding)
[1]: http://www.twitter.com/josueencinar


<!-- Grab your social icons from https://github.com/carlsednaoui/gitsocial -->
