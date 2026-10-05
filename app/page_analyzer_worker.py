import json,sys
from .page_analyzer import analyze_html
def main():
    request=json.loads(sys.stdin.read()); sys.stdout.write(json.dumps(analyze_html(str(request.get("html","")),str(request.get("base_url",""))),ensure_ascii=False)); return 0
if __name__=="__main__": raise SystemExit(main())