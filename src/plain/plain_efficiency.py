#!/usr/bin/env python3
import torch
import torchvision
import torchvision.transforms as transforms
import time
import numpy as np
from torch.utils.data import DataLoader
import os
import json
import psutil
import os
import matplotlib.pyplot as plt
import base64
from io import BytesIO

def get_memory_usage():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024 / 1024  # MB

def test_cifar10_efficiency():
    model = torch.hub.load("chenyaofo/pytorch-cifar-models", "cifar10_resnet20", pretrained=True, verbose=False)
    model.eval()
    
    #数据预处理
    transform = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize((0.4914, 0.4822, 0.4465), (0.2023, 0.1994, 0.2010))
    ])
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))  
    data_dir = os.path.join(project_root, 'data')

    # print(data_dir)

    testset = torchvision.datasets.CIFAR10(root=data_dir, train=False, download=True, transform=transform)
    testloader = DataLoader(testset, batch_size=100, shuffle=False, num_workers=2)
    

    total_images = 10000  
    test_batches = 100    
    
    print("=== CIFAR-10明文测试 ===")
    print(f"测试集大小: {total_images}张图像")
    print(f"批次大小: 100")
    print(f"测试批次: {test_batches}")
    print("=" * 50)
  
    correct = 0
    total = 0
    total_time = 0.0
    memory_usage_list = []  # 记录每个批次的内存消耗
    
    print("开始性能测试...")
    # 在测试前后记录内存
    mem_before = get_memory_usage()
    memory_usage_list.append(mem_before)

    with torch.no_grad():
        for i, (images, labels) in enumerate(testloader):
            if i >= test_batches: 
                break
                
            batch_start = time.time()
            
            outputs = model(images)
            _, predicted = torch.max(outputs.data, 1)
            
            batch_time = time.time() - batch_start
            
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
            total_time += batch_time
            
            # 记录当前批次的内存消耗
            current_mem = get_memory_usage()
            memory_usage_list.append(current_mem)
            
            if (i + 1) % 10 == 0:
                accuracy = 100.0 * correct / total
                avg_time = total_time / total
                print(f"批次 {i+1}/{test_batches} - 准确率: {accuracy:.2f}% - 平均时间: {avg_time*1000:.2f}ms/张")
    
    accuracy = 100.0 * correct / total
    avg_time_per_image = total_time / total
    images_per_second = total / total_time
    
    # ... 运行测试 ...
    mem_after = get_memory_usage()
    memory_usage_list.append(mem_after)
    
    # 计算内存使用相关统计数据
    memory_peak_mb = max(memory_usage_list) if memory_usage_list else 0
    memory_avg_mb = sum(memory_usage_list) / len(memory_usage_list) if memory_usage_list else 0

    print("=" * 50)
    print("=== 测试结果 ===")
    print(f"测试图像数量: {total}")
    print(f"正确分类: {correct}")
    print(f"准确率: {accuracy:.2f}%")
    print(f"总时间: {total_time:.2f}秒")
    print(f"平均推理时间: {avg_time_per_image*1000:.2f}毫秒/张")
    print(f"推理速度: {images_per_second:.2f}张/秒")
    print(f"推理速度: {images_per_second*60:.2f}张/分钟")
    print(f'内存峰值: {mem_after - mem_before:.2f}MB')
    print("=" * 50)

    result = {
        "total_images": total,
        "correct": correct,
        "accuracy": round(accuracy, 2),
        "total_time_sec": round(total_time, 2),
        "avg_time_ms_per_image": round(avg_time_per_image * 1000, 2),
        "images_per_second": round(images_per_second, 2),
        "memory_peak_mb": round(memory_peak_mb, 2),
        "memory_avg_mb": round(memory_avg_mb, 2),
        "memory_usage_list": [round(mem, 2) for mem in memory_usage_list]
    }

    print("\nJSON_RESULT_START")
    print(json.dumps(result))
    print("JSON_RESULT_END")


if __name__ == "__main__":
    test_cifar10_efficiency()