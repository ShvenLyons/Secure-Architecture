import numpy as np
import pandas as pd
import os
from gensim.models import Word2Vec
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from tqdm import tqdm
import time
import warnings
import joblib
warnings.filterwarnings("ignore")

# ========== 设置路径 ==========
train_path = "./data/UNSW/train/Payload_data_UNSW_train_split_binary.csv"
test_path = "./data/UNSW/test/Payload_data_UNSW_test_split_binary.csv"
w2v_model_path = "model/Joint/UNSW.model"
rf_model_path = "model/Joint/UNSW.pkl"

# ========== 加载数据 ==========
if not os.path.exists(train_path) or not os.path.exists(test_path):
    raise FileNotFoundError("❌ 训练或测试集文件未找到")

df_train_full = pd.read_csv(train_path)
df_test_full = pd.read_csv(test_path)

# ========== 分层抽样函数 ==========
def stratified_sample(df, label_col, sample_size):
    grouped = df.groupby(label_col, group_keys=False)
    total_size = len(df)
    frac = sample_size / total_size
    return grouped.apply(lambda x: x.sample(
        frac=frac,
        replace=(frac > 1),
        random_state=42
    ))

# ========== 采样 ==========
df_train = stratified_sample(df_train_full, 'label', 100_000)
df_test = stratified_sample(df_test_full, 'label', 10_000)

print(f"✅ 训练集采样完成: {len(df_train)} 条")
print(df_train['label'].value_counts(normalize=True))
print(f"✅ 测试集采样完成: {len(df_test)} 条")
print(df_test['label'].value_counts(normalize=True))

# ========== 提取 payload 字段 ==========
feature_cols = [col for col in df_train.columns if col.startswith("payload_byte_")]
if len(feature_cols) != 1500:
    raise ValueError("❌ payload 字段数不为1500，请检查数据格式")
print(f"✅ payload 提取完成")

# ========== 转换为 token 序列 ==========
tokens_train = df_train[feature_cols].astype(str).values.tolist()
tokens_test = df_test[feature_cols].astype(str).values.tolist()
print(f"✅ token 序列完成")

# ========== 训练 Word2Vec ==========
w2v = Word2Vec(sentences=tokens_train, vector_size=32, window=3, min_count=1)
os.makedirs(os.path.dirname(w2v_model_path), exist_ok=True)
w2v.save(w2v_model_path)
print(f"✅ Word2Vec 模型已保存为: {w2v_model_path}")

# ========== 嵌入函数 ==========
def embed(tokens):
    vecs = [w2v.wv[t] for t in tokens if t in w2v.wv]
    return np.mean(vecs, axis=0) if vecs else np.zeros(w2v.vector_size)

train_embeds = np.vstack([embed(seq) for seq in tokens_train])
test_embeds = np.vstack([embed(seq) for seq in tokens_test])
print("✅ 嵌入完成，训练集:", train_embeds.shape, "测试集:", test_embeds.shape)

# ========== 模型训练 ==========
y_train = df_train['label'].values
y_test = df_test['label'].values

rf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
print("🌲 正在训练随机森林...")
start = time.time()
rf.fit(train_embeds, y_train)
print("✅ 训练完成，用时 {:.2f} 秒".format(time.time() - start))

# ========== 保存 RF 模型 ==========
joblib.dump(rf, rf_model_path)
print(f"💾 RF 模型已保存为: {rf_model_path}")

# ========== 模型预测 ==========
print("🔍 正在进行预测...")
y_pred = rf.predict(test_embeds)

acc = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, digits=4)
print("🎯 测试集准确率: {:.4f}".format(acc))
print("📋 分类报告:\n", report)
