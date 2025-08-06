# Project 5
## 一、数学基础
### 1、椭圆曲线方程
SM2采用定义在素域Fp上的椭圆曲线，其方程为：y^2 = x^3 + ax + b mod p。
### 2、椭圆曲线点运算
点加运算：P + Q
点倍运算：2P
标量乘法：kP = P + P + …… + P
标量乘法是ECC的核心运算，其安全性基于椭圆曲线离散对数问题(ECDLP) 的困难性：已知点P和Q = kP，求整数k在计算上不可行。
## 二、数字签名算法
### 1、密钥生成
私钥：随机整数d∈[1, n-1]
公钥：椭圆曲线点P = dG
### 2、签名过程
设待签名消息为M，用户私钥为d。<br>
(1)计算e = SM3(M)，转换为整数<br>
(2)生成随机数k∈[1, n-1]<br>
(3)计算椭圆曲线点(x1, y1) = kG<br>
(4)计算r = (e + x1) mod n，若r = 0或r + k = n则返回步骤2<br>
(5)计算s = (1 + d)^{-1} * (k - r * d) \mod n，若s = 0则返回步骤2<br>
(6)输出签名(r, s)<br>
<img width="1989" height="468" alt="image" src="https://github.com/user-attachments/assets/9db77f89-8b24-4fd4-ad5f-13ee345255c9" />
