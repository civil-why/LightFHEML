#!/usr/bin/env python3
import sys

if len(sys.argv) == 1:
    print('程序中缺少图像文件名 (例如： \'plain.py "../inputs/luis.png"\')')
    exit(0)

import torch
from torchvision import transforms
from PIL import Image
import numpy as np

CLASSES = ['飞机', '汽车', '鸟', '猫', '鹿',
           '狗', '青蛙', '马', '船', '卡车']


model = torch.hub.load("chenyaofo/pytorch-cifar-models", "cifar10_resnet20", pretrained = True, verbose=False)
model.eval()

img = Image.open(sys.argv[1])
convert_tensor = transforms.ToTensor()
img = convert_tensor(img)
img = img.unsqueeze(0)

np.set_printoptions(precision=3)
np.set_printoptions(formatter={'all': lambda x: repr(x)})

result = model(img)

# 将结果转换为普通double类型
result_list = [float(np.around(x, 3)) for x in result[0].detach().numpy()]

# 找到最大值和对应的类别
max_value = max(result_list)
max_index = result_list.index(max_value)
predicted_class = CLASSES[max_index]

# 输出结果给后端处理
print("JSON_RESULT_START")
print('{"概率分布": "' + str(result_list) + '",')
print('"预测类别": "' + predicted_class + '",')
print('"置信度": ' + str(max_value) + '}')
print("JSON_RESULT_END")