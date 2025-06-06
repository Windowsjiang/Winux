#!usr/bin/sh
f=~/usr/recpl/Cache/$fname$.djwe
cp ~/usr/recpl/Cache/$fname$.djwe ~/usr/recpl/Cache/$fname$.tmp
exec ~/usr/recpl/bitutils/bitutils/objdump -C ~/usr/recpl/Cache/$fname$.tmp > ~/usr/recpl/Cache/$fname$.c