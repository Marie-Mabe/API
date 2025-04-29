@echo off
echo Installation des dependances...
pip install -r requirements.txt
pip install pyinstaller

echo Creation de l'executable...
pyinstaller --onefile --name detectfraude_api --add-data "src;src" --add-data "D:/JupyterNote/xgb_model.pkl;." run.py

echo Copie des fichiers necessaires...
xcopy /y /i "dist\detectfraude_api.exe" "release\"
xcopy /y /i "D:/JupyterNote/xgb_model.pkl" "release\"

echo Construction terminee !
pause 