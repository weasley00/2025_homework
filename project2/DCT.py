import cv2
import numpy as np
import argparse
import os
from typing import Tuple

# ---------------------------- 工具函数 ----------------------------

def to_gray(img: np.ndarray) -> np.ndarray:
    if img.ndim == 3:
        return cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    return img.copy()


def normalized_correlation(a: np.ndarray, b: np.ndarray) -> float:
    a = a.flatten().astype(np.float64)
    b = b.flatten().astype(np.float64)
    a -= a.mean()
    b -= b.mean()
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)

# ---------------------------- DCT水印方法 ----------------------------
# 基本思路：
# 1) 将灰度图像划分为 8x8 块
# 2) 对每个块做DCT（cv2.dct）
# 3) 在中频系数对（例如 (3,2) 和 (2,3)）中按照水印位微调系数差值来嵌入
# 4) 做IDCT重建图像
# 取块的顺序可以采用行优先，也可以用伪随机序列（带密钥）来提高安全性

BLOCK = 8


def _block_iter(img: np.ndarray, block_size: int = BLOCK):
    h, w = img.shape
    for y in range(0, h - block_size + 1, block_size):
        for x in range(0, w - block_size + 1, block_size):
            yield y, x, img[y:y + block_size, x:x + block_size]


def embed_watermark_dct(cover: np.ndarray, watermark: np.ndarray, alpha=10, key: int = 0) -> np.ndarray:
    """
    将二值水印嵌入到灰度cover图像的DCT中。
    watermark：应为二值图（0/1），尺寸小于等于cover划分的块数（或会重复/裁剪）
    alpha：控制嵌入强度（越大越鲁棒，但失真越明显）
    key：伪随机顺序的种子（用于块序列打乱）
    返回嵌入后图像（灰度）
    """
    cover_gray = to_gray(cover).astype(np.float32)
    h, w = cover_gray.shape

    # 将水印拉平为bit序列
    wm = to_gray(watermark)
    _, wm_bin = cv2.threshold(wm, 127, 1, cv2.THRESH_BINARY)
    wm_bits = wm_bin.flatten()
    n_bits = wm_bits.size

    # 计算可用块数量
    blocks = []
    for y in range(0, h - BLOCK + 1, BLOCK):
        for x in range(0, w - BLOCK + 1, BLOCK):
            blocks.append((y, x))

    if len(blocks) == 0:
        raise ValueError('Cover image too small for block size')

    seed = key
    rng = np.random.default_rng(seed)
    perm = np.arange(len(blocks))
    rng.shuffle(perm)

    stego = cover_gray.copy()

    for i in range(n_bits):
        block_idx = perm[i % len(perm)]
        y, x = blocks[block_idx]
        block = cover_gray[y:y + BLOCK, x:x + BLOCK]
        dct_block = cv2.dct(block)

        # 选取两个中频系数
        # 位置可以调整以提高鲁棒性/不可见性
        (u1, v1) = (2, 3)
        (u2, v2) = (3, 2)
        c1 = dct_block[u1, v1]
        c2 = dct_block[u2, v2]

        bit = wm_bits[i]
        # 通过调整c1-c2的差距来编码1或0
        if bit == 1:
            if c1 <= c2:
                diff = (c2 - c1) + alpha
                dct_block[u1, v1] = c1 + diff / 2
                dct_block[u2, v2] = c2 - diff / 2
        else:
            if c1 >= c2:
                diff = (c1 - c2) + alpha
                dct_block[u1, v1] = c1 - diff / 2
                dct_block[u2, v2] = c2 + diff / 2

        idct_block = cv2.idct(dct_block)
        stego[y:y + BLOCK, x:x + BLOCK] = idct_block

    # 裁剪并转为uint8
    stego = np.clip(stego, 0, 255).astype(np.uint8)
    return stego


def extract_watermark_dct(stego: np.ndarray, wm_shape: Tuple[int, int], alpha=10, key: int = 0) -> np.ndarray:
    """
    从stego中提取水印（假设与嵌入时参数一致）。
    返回一个二值水印图像（0/255）
    """
    gray = to_gray(stego).astype(np.float32)
    h, w = gray.shape

    wm_bits = []

    blocks = []
    for y in range(0, h - BLOCK + 1, BLOCK):
        for x in range(0, w - BLOCK + 1, BLOCK):
            blocks.append((y, x))

    seed = key
    rng = np.random.default_rng(seed)
    perm = np.arange(len(blocks))
    rng.shuffle(perm)

    n_bits = wm_shape[0] * wm_shape[1]

    for i in range(n_bits):
        block_idx = perm[i % len(perm)]
        y, x = blocks[block_idx]
        block = gray[y:y + BLOCK, x:x + BLOCK]
        dct_block = cv2.dct(block)
        (u1, v1) = (2, 3)
        (u2, v2) = (3, 2)
        c1 = dct_block[u1, v1]
        c2 = dct_block[u2, v2]
        bit = 1 if c1 > c2 else 0
        wm_bits.append(bit)

    wm_bits = np.array(wm_bits[:n_bits], dtype=np.uint8)
    wm_img = (wm_bits.reshape(wm_shape) * 255).astype(np.uint8)
    return wm_img

# ---------------------------- 常见攻击（鲁棒性测试） ----------------------------


def attack_flip(img: np.ndarray, mode: str) -> np.ndarray:
    if mode == 'h':
        return cv2.flip(img, 1)
    elif mode == 'v':
        return cv2.flip(img, 0)
    elif mode == 'hv':
        return cv2.flip(img, -1)
    else:
        raise ValueError('Unknown flip mode')


def attack_translate(img: np.ndarray, tx: int, ty: int) -> np.ndarray:
    h, w = img.shape[:2]
    M = np.float32([[1, 0, tx], [0, 1, ty]])
    return cv2.warpAffine(img, M, (w, h), borderMode=cv2.BORDER_REFLECT)


def attack_crop(img: np.ndarray, crop_fraction: float) -> np.ndarray:
    # crop_fraction表示保留中心区域的比例，例如0.8表示保留80%的中心区域
    h, w = img.shape[:2]
    ch = int(h * crop_fraction)
    cw = int(w * crop_fraction)
    y0 = (h - ch) // 2
    x0 = (w - cw) // 2
    cropped = img[y0:y0 + ch, x0:x0 + cw]
    # 将裁剪后的图片放回到原始尺寸的画布中心，四周填充镜像或黑
    canvas = np.zeros_like(img)
    y1 = (h - ch) // 2
    x1 = (w - cw) // 2
    canvas[y1:y1 + ch, x1:x1 + cw] = cropped
    return canvas


def attack_contrast(img: np.ndarray, alpha: float = 1.0, beta: float = 0.0) -> np.ndarray:
    # new = img * alpha + beta
    out = img.astype(np.float32) * alpha + beta
    out = np.clip(out, 0, 255).astype(np.uint8)
    return out


def attack_gaussian_noise(img: np.ndarray, sigma: float = 10.0) -> np.ndarray:
    gauss = np.random.normal(0, sigma, img.shape).astype(np.float32)
    out = img.astype(np.float32) + gauss
    out = np.clip(out, 0, 255).astype(np.uint8)
    return out

# ---------------------------- 测试与评估 ----------------------------


def robustness_test(stego_path: str, original_wm_path: str, output_dir: str, alpha=10, key=0):
    os.makedirs(output_dir, exist_ok=True)
    stego = cv2.imread(stego_path, cv2.IMREAD_COLOR)
    if stego is None:
        raise FileNotFoundError(stego_path)
    stego_gray = to_gray(stego)

    wm = cv2.imread(original_wm_path, cv2.IMREAD_GRAYSCALE)
    if wm is None:
        raise FileNotFoundError(original_wm_path)

    wm_shape = (wm.shape[0], wm.shape[1])

    attacks = []
    attacks.append(('no_attack', stego_gray.copy()))
    attacks.append(('flip_h', attack_flip(stego_gray, 'h')))
    attacks.append(('flip_v', attack_flip(stego_gray, 'v')))
    attacks.append(('flip_hv', attack_flip(stego_gray, 'hv')))
    attacks.append(('translate_10_5', attack_translate(stego_gray, 10, 5)))
    attacks.append(('translate_-7_12', attack_translate(stego_gray, -7, 12)))
    attacks.append(('crop_0.9', attack_crop(stego_gray, 0.9)))
    attacks.append(('crop_0.7', attack_crop(stego_gray, 0.7)))
    attacks.append(('contrast_1.2', attack_contrast(stego_gray, alpha=1.2, beta=0)))
    attacks.append(('contrast_0.8', attack_contrast(stego_gray, alpha=0.8, beta=10)))
    attacks.append(('gauss_10', attack_gaussian_noise(stego_gray, sigma=10)))

    results = []
    for name, img in attacks:
        wm_ex = extract_watermark_dct(img, wm_shape, alpha=alpha, key=key)
        corr = normalized_correlation((wm > 127).astype(np.uint8), (wm_ex > 127).astype(np.uint8))
        results.append((name, corr, wm_ex))
        out_path = os.path.join(output_dir, f'extracted_{name}.png')
        cv2.imwrite(out_path, wm_ex)
        cv2.imwrite(os.path.join(output_dir, f'attacked_{name}.png'), img)

    # 打印结果
    print('鲁棒性测试结果 (Normalized Correlation):')
    for name, corr, _ in results:
        print(f'{name:20s}  {corr:.4f}')

    return results

# ---------------------------- 命令行接口 ----------------------------


def main():
    parser = argparse.ArgumentParser(description='DCT-based image watermark embed/extract and robustness test')
    parser.add_argument('--embed', nargs=3, metavar=('COVER', 'WATERMARK', 'OUT'), help='Embed watermark')
    parser.add_argument('--extract', nargs=3, metavar=('STEGO', 'WMSHAPE_H', 'WMSHAPE_W'), help='Extract watermark')
    parser.add_argument('--test', nargs=2, metavar=('STEGO', 'WATERMARK'), help='Run robustness tests on stego')
    parser.add_argument('--alpha', type=float, default=10.0, help='Embedding strength')
    parser.add_argument('--key', type=int, default=0, help='Key for pseudo-random block permutation')
    parser.add_argument('--outdir', type=str, default='results', help='Output directory for tests')
    args = parser.parse_args()

    if args.embed:
        cover_path, wm_path, out_path = args.embed
        cover = cv2.imread(cover_path, cv2.IMREAD_COLOR)
        if cover is None:
            raise FileNotFoundError(cover_path)
        wm = cv2.imread(wm_path, cv2.IMREAD_GRAYSCALE)
        if wm is None:
            raise FileNotFoundError(wm_path)
        stego = embed_watermark_dct(cover, wm, alpha=args.alpha, key=args.key)
        cv2.imwrite(out_path, stego)
        print(f'嵌入完成，保存为: {out_path}')

    elif args.extract:
        stego_path, h_str, w_str = args.extract
        stego = cv2.imread(stego_path, cv2.IMREAD_COLOR)
        if stego is None:
            raise FileNotFoundError(stego_path)
        h = int(h_str); w = int(w_str)
        wm_ex = extract_watermark_dct(stego, (h, w), alpha=args.alpha, key=args.key)
        out = os.path.splitext(stego_path)[0] + '_extracted.png'
        cv2.imwrite(out, wm_ex)
        print(f'提取完成，保存为: {out}')

    elif args.test:
        stego_path, wm_path = args.test
        robustness_test(stego_path, wm_path, args.outdir, alpha=args.alpha, key=args.key)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
