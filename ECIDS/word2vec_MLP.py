import numpy as np
import pandas as pd
import os
from gensim.models import Word2Vec
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm
import time, warnings, joblib
warnings.filterwarnings("ignore")

# ========== 设置路径 ==========
train_path = "./data/UNSW/train/Payload_data_UNSW_train_split_binary.csv"
test_path  = "./data/UNSW/test/Payload_data_UNSW_test_split_binary.csv"
w2v_model_path = "model/Joint/UNSW.model"
mlp_model_path = "model/Joint/UNSW_MLP.pkl"

# ========== 加载数据 ==========
if not os.path.exists(train_path) or not os.path.exists(test_path):
    raise FileNotFoundError("❌ 训练或测试集文件未找到")

df_train_full = pd.read_csv(train_path)
df_test_full  = pd.read_csv(test_path)

# ========== 分层抽样函数 ==========
def stratified_sample(df, label_col, sample_size):
    grouped = df.groupby(label_col, group_keys=False)
    frac = sample_size / len(df)
    return grouped.apply(lambda x: x.sample(frac=frac,
                                            replace=(frac > 1),
                                            random_state=42))

df_train = stratified_sample(df_train_full, 'label', 100_000)
df_test  = stratified_sample(df_test_full,  'label', 10_000)

# ========== 提取 payload 字段 ==========
feature_cols = [c for c in df_train.columns if c.startswith("payload_byte_")]
if len(feature_cols) != 1500:
    raise ValueError("❌ payload 字段数不为1500，请检查数据格式")

# ========== 转换为 token 序列 ==========
tokens_train = df_train[feature_cols].astype(str).values.tolist()
tokens_test  = df_test[feature_cols].astype(str).values.tolist()

# ========== 训练 Word2Vec ==========
w2v = Word2Vec(sentences=tokens_train,
               vector_size=32, window=3, min_count=1)
os.makedirs(os.path.dirname(w2v_model_path), exist_ok=True)
w2v.save(w2v_model_path)
print(f"✅ Word2Vec 已保存: {w2v_model_path}")

# ========== 嵌入函数 ==========
def embed(tokens):
    vecs = [w2v.wv[t] for t in tokens if t in w2v.wv]
    return np.mean(vecs, axis=0) if vecs else np.zeros(w2v.vector_size)

X_train = np.vstack([embed(seq) for seq in tokens_train])
X_test  = np.vstack([embed(seq) for seq in tokens_test])
y_train = df_train['label'].values
y_test  = df_test['label'].values

# ★★★（可选）特征标准化 ★★★
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# ========== 训练 MLP ==========
mlp = MLPClassifier(hidden_layer_sizes=(128, 64),
                    activation='relu',
                    solver='adam',
                    batch_size='auto',
                    learning_rate_init=1e-3,
                    max_iter=50,
                    random_state=42,
                    early_stopping=True,
                    verbose=False)
print("🤖 正在训练 MLP...")
start = time.time()
mlp.fit(X_train, y_train)
print(f"✅ 训练完成，用时 {time.time() - start:.2f} 秒")

# ========== 保存模型 ==========
joblib.dump({'model': mlp, 'scaler': scaler}, mlp_model_path)
print(f"💾 MLP 模型已保存为: {mlp_model_path}")

# ========== 评估 ==========
print("🔍 开始预测...")
y_pred = mlp.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"🎯 测试集准确率: {acc:.4f}")
print("📋 分类报告:\n", classification_report(y_test, y_pred, digits=4))
