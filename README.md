# Padding Oracle attack against Cipertext Block Chaining (CBC) with PKCS#5 Padding

I wrote this demo back in 2011:
* https://www.youtube.com/watch?v=B7UzYaTSeq8
* https://www.slideshare.net/blaufish/padding-oracle-opkoko2011

Sadly, the source code could not be found anywhere today.

So I rewrote it, largely based on OCR:s from the youtube screenshots.

The code was largely inspired by articles by:
* Juliano Rizzo, Thai Duong
* Brian Holyfield

The vulnerability was originally described in 2002 by Serge Vaundenay.
Re-discoved as a prevalent problem in web encryption frameworks by Juliano Rizzo and Thai Duong.