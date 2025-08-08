# Project 6
## 结构设计
Func类：基础函数类，提供大素数生成、模幂运算、密钥生成、哈希计算和加解密等基础功能<br>
P1类：参与方 1，持有自己的密码集合，负责协议的第一轮和第三轮计算<br>
P2类：参与方 2，持有带关联值的密码集合，负责协议的第二轮计算和最终结果解密<br>
## 核心函数实现
### 大素数实现
```python
@classmethod
def _generate_large_random_prime_sympy(cls, bits):
    lower_bound = 2 **(bits - 1)
    upper_bound = 2** bits - 1
    return randprime(lower_bound, upper_bound)
```
### 模幂运算
```python
def exp_mod(self, x, e):  # x ** e (mod p)
    r = 1
    while e > 0:
        if e & 1 == 1:
            r = (r * x) % self.p
        x = (x * x) % self.p
        e >>= 1
    return r
```
### 密码哈希
```python
def hash_password(self, password):  # str->int
    sha256_hex = hashlib.sha256(password.encode()).hexdigest()
    return int(sha256_hex, 16) % self.p
```
### P1 的核心流程
```python
def round1(self):
    # 对密码哈希后进行指数运算
    hash_list = self.hash_passwords(self.password)
    hash_list = [self.exp_mod(i, self.k1) for i in hash_list]
    random.shuffle(hash_list)
    return hash_list

def round3(self):
    # 计算匹配项的加密值之和
    P2_pass = [(self.exp_mod(tup[0], self.k1), tup[1]) for tup in self.hash_list]
    sum = None
    for pair in P2_pass:
        if pair[0] in self.Z:
            if sum is None:
                sum = pair[1]
            else:
                sum += pair[1]
    return sum
```
### P2 的核心流程
```python
def round2(self):
    # 处理接收的信息并返回中间结果
    Z = [self.exp_mod(i, self.k2) for i in self.hash_list]
    random.shuffle(Z)
    tmp = [(self.exp_mod(self.hash_password(tup[0]), self.k2), self.encrypt(tup[1], self.pk)) for tup in self.password]
    random.shuffle(tmp)
    return set(Z), tmp

def round3(self, sum):
    # 解密得到最终结果
    if sum is None:
        return 0
    all_t = self.decrypt(sum, self.sk)
    return all_t
```
## 实验步骤
初始化系统，生成大素数<br>
实例化 P1 和 P2，分别设置各自的密码集合<br>
执行三轮交互协议：<br>
第一轮：P1 处理自己的密码并发送给 P2<br>
第二轮：P2 处理接收的信息并返回中间结果<br>
第三轮：P1 计算匹配项加密值之和，P2 解密得到最终结果<br>
输出并验证结果<br>
<img width="1268" height="347" alt="image" src="https://github.com/user-attachments/assets/3a9081ef-d36f-43c2-999e-c06a68354967" />

    
