import "hash"


rule SH1
{
  condition:
   hash.sha1(0,filesize)=="da35ee96363b2ad67cfa348dd0ab6818cd512505"
    
}

rule SH2
{
  condition:
    hash.sha256(0, filesize) ==
        "744e50af5566fa5ab70d4db70d35b3b89d75018e00b6b1e8e6280030482353bc"
    
}

rule SH3
{
  condition:
    hash.sha256(0, filesize) ==
        "e7542c38e0b979f920fb88b59b25c3d6ae433ca145f7758938b322a71accecae"
    
}

rule SH4
{
  condition:
    hash.sha256(0, filesize) ==
        "72c3a786661ee9742cf1d0e3b99b89e976911ed87971695f08487cf42d7fc29d"
    
}

rule SH5
{
  condition:
    hash.md5(0, filesize) ==
        "3f748c7c4b4abb3cd90102e483f4d3c6"
    
}

rule SH6
{
  condition:
    hash.md5(0, filesize) ==
        "6cf914ebcd8a47c2b698105b751c6555"
    
}

rule SH7
{
  condition:
    hash.md5(0, filesize) ==
        "eb9943f93b672d0b4bda82d483663302"
    
}


