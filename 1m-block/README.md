# 1m-block

## db prepare
![1m-block1](https://user-images.githubusercontent.com/86241174/140961414-13abaed2-543f-4589-bf10-1446a31e595f.JPG)


## result
![1m-block2](https://user-images.githubusercontent.com/86241174/140961462-ce821632-429d-4195-8db5-512154b965f4.JPG)


## question
ocsp.pki.goog, ocsp.godaddy.com, ocsp.digicert.com 같이 ocsp를 이용한 경우 block이 정상적으로 이루어지지 않는 점 수정중 => https 처리를 잘못했습니다..ㅎ

## comment
iptable command makefile에 넣어서 저번과 같은 참사(..) 막음
sqlite3 공부만 엄청한듯

### 20211111 fix
firefox에서 hsts 옵션을 제거하여 안되던 사이트들을 block 성공함
![image](https://user-images.githubusercontent.com/86241174/141252563-a7f99595-3d86-441d-a7ca-107c9bb7afec.png)
