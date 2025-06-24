# Secure-Architecture-4-Drone

**Secure Architecture for Drone: Lightweight Packet-level IDS and Communication Encryption for MAVLink Protocol**

---
# Abstract

> - 无人机在实际应用中面临的通信安全挑战
> - 你提出的安全架构（包括轻量IDS与轻量加密）
> - 实现方法和实验评估结果

Unmanned Aerial Vehicles (UAVs) are increasingly deployed in various industrial and service applications. However, communication between drones and ground stations (D2G) is vulnerable due to protocol weaknesses. In particular, MAVLink, the widely utilized protocol for UAV control, is transmitted in plaintext with simple CRC validation mechanisms, which exposes drones to various threats such as man-in-the-middle (MITM) attacks, denial-of-service (DoS) attacks, replay attacks, and GPS spoofing.

Intrusion detection systems (IDS) and communication encryption are effective mitigation. However, existing rule-based or flow-level methods are not suitable for D2G networks due to the delay limitation, heterogeneity and dynamism of the Internet of Things. Similarly, popular encryption algorithms are impractical for resource-constrained drones under the limitation of computational overhead.

Based on these observations, we design a secure architecture for Drones that integrates two lightweight mitigation. Firstly, a packet-level IDS based on an embedder-classifier (EC) framework is proposed, which utilizes byte embeddings combined with a lightweight classifier for efficient detection. Secondly, the ASCON algorithm was used for data stream encryption, achieving secure MAVLink data transmission with minimal computational overhead. Both components are integrated into a proxy employed at the ground station to enhance security without introducing additional burdens to the Drone itself.

---
# 1. Introduction

> - 背景介绍：无人机应用快速发展，但安全性薄弱
> - MAVLink广泛应用，明文传输存在威胁
> - 项目目标：设计一套轻量化的安全通信架构
> - 论文组织结构

---
# 2. Background and Related Work

## 2.1 MAVLink Protocol Overview

> MAVLink协议基本结构、明文传输、命令类型等

## 2.2 UAV Security Threats

> 介绍针对无人机的安全攻击与研究（MITM、Replay、DoS、GPS Spoofing等）

## 2.3 IDS Lightweight Design Approaches

> IDS的轻量化设计思路与方法（可参考DroneGuard、AOC-IDS等简要提及）

## 2.4 Lightweight Encryption Techniques

> 介绍轻量级加密（如Diffie-Hellman密钥交换、对称加密流）

---
# 3. Architecture Design

## 3.1 Overall System Architecture

> 整体架构图（QGC-PX4-Gazebo仿真 + Proxy代理 + IDS模块 + 加密模块）
>
> 描述系统整体逻辑如何串联

## 3.2 Module Design and Data Flow

> - 数据采集模块 (代理监听 14550 UDP端口)
> - 攻击注入模块 (基于MAVProxy插件化架构)
> - IDS模块 (Embedding + Classifier)
> - 轻量加密模块 (密钥交换与加密封装)

## 3.3 Threat Modeling and Attack Simulation Design

### 3.3.1 Threat Modeling Approach

> 描述仿真环境与威胁场景设计：
> - D2G通信链路
> - 攻击面划分：MITM、Replay、DoS、Fake GPS

### 3.3.2 Attack Simulation Implementation

> 详细描述各类攻击的实现过程：
> - MITM (实时指令篡改)
> - Replay (任务命令重放)
> - DoS (高频指令干扰)
> - Fake GPS (虚假位置数据注入)

### 3.3.3 Evaluation Consideration

> 攻击实施时间、持续时间、实验观测点等设计说明

---
# 4. Implementation

## 4.1. ECIDS

### 4.1.1 Data Collection and Feature Extraction

> - 攻击模拟流量采集过程
> - 数据结构说明（如payload_hex、mav_payload）
> - IDS模块说明（embedder + classifier）

### 4.1.2 EC Framework Design (Embedding + Classifier)

> - 嵌入层设计 (Word2Vec嵌入向量)
> - 分类器选择 (轻量MLP / RF / DT均可)
> - 模型训练流程（不展开SFT等研究性训练）

### 4.1.3 Experiment

> - 实验设置
> - 使用指标（Accuracy, F1-score, AUC, Processing Time）
> - 结果与分析

## 4.2. Lightweight Encryption

### 4.2.1 Diffie-Hellman Based Key Exchange

> 描述密钥协商过程

### 4.2.2 Communication Encryption Scheme

> - 明文MAVLink数据流的加密封装
> - 加密算法选型（轻量对称加密，如AES-CTR，ascon）
> - 加密封装与解封装逻辑

### 4.2.3 Experiment

> - 加密带来的延迟开销分析
> - 对数据完整性、兼容性的影响分析

---

# 5. Integrated System Evaluation

> - 将IDS与加密模块整合后，进行综合测试
> - 真实环境下测试结果汇总
> - 工程可部署性分析

---

# 6. Conclusion

> 总结项目工作：
> - 提出了完整的无人机安全架构
> - 实现了轻量的packet-level IDS与轻量通信加密模块
> - 在真机仿真环境中完成了多种攻击模拟与防护验证
> - 提出后续改进方向（如迁移学习、多攻击协同检测）

---

# References

> 参考文献

---

# Appendix

- 攻击指令集示例
- 攻击流程示意图
- 数据采集示例样本
- 系统架构与加密流程图

