import numpy as np
import pickle
import os

def unpickle(file):
    with open(file, 'rb') as fo:
        dict = pickle.load(fo, encoding='bytes')
    return dict

# 转换测试集（同理可转换训练集）
data = unpickle('cifar-10-batches-py/test_batch')
images = data[b'data']        # shape: (10000, 3072)
labels = data[b'labels']      # list of 10000 labels

# 保存为二进制：先存图像数量，再依次存图像数据和标签
with open('cifar10_test.bin', 'wb') as f:
    # 写入样本数（int32）
    f.write(np.array([len(images)], dtype=np.int32).tobytes())
    # 写入所有图像数据（float32，归一化到[0,1]）
    images_float = images.reshape(-1, 3, 32, 32).astype(np.float32) / 255.0
    f.write(images_float.tobytes())
    # 写入所有标签（int32）
    f.write(np.array(labels, dtype=np.int32).tobytes())