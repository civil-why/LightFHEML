#!/usr/bin/env python3
import torch
import torchvision
import torchvision.transforms as transforms
import time
import numpy as np
from torch.utils.data import DataLoader
import os

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
    
    print("开始性能测试...")
    
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
            
            if (i + 1) % 10 == 0:
                accuracy = 100.0 * correct / total
                avg_time = total_time / total
                print(f"批次 {i+1}/{test_batches} - 准确率: {accuracy:.2f}% - 平均时间: {avg_time*1000:.2f}ms/张")
    
    accuracy = 100.0 * correct / total
    avg_time_per_image = total_time / total
    images_per_second = total / total_time
    
    print("=" * 50)
    print("=== 测试结果 ===")
    print(f"测试图像数量: {total}")
    print(f"正确分类: {correct}")
    print(f"准确率: {accuracy:.2f}%")
    print(f"总时间: {total_time:.2f}秒")
    print(f"平均推理时间: {avg_time_per_image*1000:.2f}毫秒/张")
    print(f"推理速度: {images_per_second:.2f}张/秒")
    print(f"推理速度: {images_per_second*60:.2f}张/分钟")
    print("=" * 50)

if __name__ == "__main__":
    test_cifar10_efficiency()
