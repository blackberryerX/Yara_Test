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
        "8cabc861a04b1bad7bc7daf997bac4a013a457a52bc7aa40f925182da4797d8d"
    
}

rule SH4
{
  condition:
    hash.sha256(0, filesize) ==
        "43ce41be6eeaf3aa61a0ff9a28c045c75e6a104449a145a154eaaa6f36fda44f"
    
}

rule SH5
{
  condition:
    hash.md5(0, filesize) ==
        "bd8344d3e2020669dd235bb644751d76"
    
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


