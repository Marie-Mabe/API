from src.app import app
import os

if __name__ == '__main__':
    # Créer le dossier pour les fichiers temporaires si nécessaire
    if not os.path.exists('temp'):
        os.makedirs('temp')
    
    # Lancer l'application en mode production
    app.run(host='0.0.0.0', port=5000, debug=False) 