from __future__ import annotations
from pathlib import Path
import joblib,numpy as np
from sklearn.base import BaseEstimator,TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion,Pipeline
from sklearn.preprocessing import StandardScaler
from .detector import extract_features
MODEL_VERSION="3.0.0"
DEFAULT_MODEL_PATH=Path(__file__).resolve().parent.parent/"models"/"phishing_url_model.joblib"
class URLNumericFeatures(BaseEstimator,TransformerMixin):
    FEATURE_NAMES=["url_length","host_length","path_length","query_length","dot_count","hyphen_count","underscore_count","at_count","percent_count","slash_count","digit_ratio","subdomain_count","has_ip_host","has_punycode","uses_https","suspicious_word_count","suspicious_tld"]
    def fit(self,X,y=None): return self
    def transform(self,X): return np.asarray([[float(extract_features(str(url))[name]) for name in self.FEATURE_NAMES] for url in X],dtype=float)
class URLModel:
    def __init__(self,pipeline,metadata=None): self.pipeline=pipeline; self.metadata=metadata or {"model_version":MODEL_VERSION}
    def predict_proba(self,urls): return self.pipeline.predict_proba(urls)
    def save(self,path=DEFAULT_MODEL_PATH):
        path=Path(path); path.parent.mkdir(parents=True,exist_ok=True); joblib.dump(self,path); return path
    @classmethod
    def load(cls,path=DEFAULT_MODEL_PATH): return joblib.load(path)
def build_pipeline():
    lexical=TfidfVectorizer(analyzer="char",ngram_range=(3,5),min_df=1,sublinear_tf=True,max_features=25000)
    numeric=Pipeline([("features",URLNumericFeatures()),("scale",StandardScaler())])
    features=FeatureUnion([("char_tfidf",lexical),("numeric",numeric)])
    return Pipeline([("features",features),("classifier",LogisticRegression(max_iter=2000,class_weight="balanced",random_state=42))])
def train_model(urls,labels):
    pipeline=build_pipeline(); pipeline.fit(urls,labels)
    return URLModel(pipeline,{"model_version":MODEL_VERSION,"feature_set":"character TF-IDF (3-5 grams) + engineered URL features","classifier":"LogisticRegression"})