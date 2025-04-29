from flask import Flask, request, jsonify, send_file
from db import get_db_connection
import pandas as pd
import joblib
import os
import jwt
from functools import wraps
from datetime import datetime, timedelta, timezone
import csv
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
model = joblib.load("D:/JupyterNote/xgb_model.pkl")
print("Features utilisées par le modèle :", model.get_booster().feature_names)

# Configuration de la clé secrète pour JWT
app.config['SECRET_KEY'] = "votre_cle_secrete_123"

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            print("Erreur : Token manquant")
            return jsonify({"error": "Token manquant"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data["user_id"]
            role = data["role"]
        except Exception as e:
            print("Erreur : Token invalide -", str(e))
            return jsonify({"error": "Token invalide : " + str(e)}), 401
        return f(current_user_id, role, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user_id, role, *args, **kwargs):
        if role != "admin":
            print(f"Accès non autorisé : rôle={role}, requis=admin")
            return jsonify({"error": "Accès non autorisé : administrateur requis"}), 403
        return f(current_user_id, role, *args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('mot_de_passe'):
        return jsonify({'error': 'Email et mot de passe requis'}), 400

    email = data.get('email')
    mot_de_passe = data.get('mot_de_passe')

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, nom, email, mot_de_passe, role FROM utilisateurs WHERE email = %s", (email,))
                user = cursor.fetchone()

                if not user:
                    return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

                if not bcrypt.check_password_hash(user[3], mot_de_passe):
                    return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

                # Création du token JWT avec datetime.now(UTC)
                token = jwt.encode({
                    'user_id': user[0],
                    'email': user[2],
                    'role': user[4],
                    'exp': datetime.now(timezone.utc) + timedelta(hours=24)
                }, app.config['SECRET_KEY'], algorithm='HS256')

                return jsonify({
                    'token': token,
                    'user': {
                        'id': user[0],
                        'nom': user[1],
                        'email': user[2],
                        'role': user[4]
                    }
                }), 200

    except Exception as e:
        print(f"Erreur détaillée lors de la connexion : {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Erreur lors de la connexion'}), 500

@app.route('/signup', methods=['POST'])
def signup():
    conn = None
    cursor = None
    try:
        data = request.get_json()
        print("Données reçues pour l'inscription:", data)
        
        if not data or not all(k in data for k in ['nom', 'email', 'mot_de_passe']):
            return jsonify({'error': 'Données manquantes'}), 400

        nom = data['nom']
        email = data['email']
        mot_de_passe = data['mot_de_passe']

        # Vérifier si l'email existe déjà
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM utilisateurs WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({'error': 'Email déjà utilisé'}), 400

        # Hasher le mot de passe
        hashed_password = bcrypt.generate_password_hash(mot_de_passe).decode('utf-8')

        # Insérer le nouvel utilisateur avec le rôle 'user' par défaut
        cursor.execute(
            "INSERT INTO utilisateurs (nom, email, mot_de_passe, role) VALUES (%s, %s, %s, %s)",
            (nom, email, hashed_password, 'user')
        )
        
        # Créer le compte associé
        user_id = cursor.lastrowid
        cursor.execute("INSERT INTO comptes (user_id, solde) VALUES (%s, %s)", (user_id, 0))
        
        conn.commit()
        return jsonify({'message': 'Inscription réussie'}), 201

    except Exception as e:
        print(f"Erreur détaillée lors de l'inscription: {str(e)}")
        if conn:
            conn.rollback()
        return jsonify({'error': f'Erreur lors de l\'inscription: {str(e)}'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def calculate_fraud_score(transaction_data):
    # Basé sur l'écart par rapport à la moyenne et au maximum historique
    if not transaction_data['is_usual_amount']:
        # Plus l'écart est grand, plus le score est élevé
        avg_amount = transaction_data['avg_amount']
        max_amount = transaction_data['max_amount']
        current_amount = transaction_data['current_amount']
        
        # Calculer l'écart par rapport à la moyenne et au maximum
        deviation_from_avg = (current_amount - avg_amount) / avg_amount if avg_amount > 0 else 1.0
        deviation_from_max = (current_amount - max_amount) / max_amount if max_amount > 0 else 1.0
        
        # Le score est la moyenne des deux écarts, limité à 1.0
        return min((deviation_from_avg + deviation_from_max) / 2, 1.0)
    return 0.0

@app.route("/predict", methods=["POST"])
@token_required
def predict_transaction(current_user_id, role):
    try:
        data = request.get_json()
        print("Données reçues pour la prédiction:", data)
        
        if not data or not all(k in data for k in ['montant', 'user_id', 'destinataire_id', 'mot_de_passe']):
            return jsonify({'error': 'Données manquantes'}), 400

        montant = float(data['montant'])
        user_id = int(data['user_id'])
        destinataire_id = int(data['destinataire_id'])
        mot_de_passe = data['mot_de_passe']

        # Vérifier que l'utilisateur fait la transaction pour lui-même
        if current_user_id != user_id:
            return jsonify({'error': 'Utilisateur non autorisé'}), 403

        # Vérifier le mot de passe
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT mot_de_passe FROM utilisateurs WHERE id = %s", (user_id,))
        stored_password = cursor.fetchone()[0]
        
        if not bcrypt.check_password_hash(stored_password, mot_de_passe):
            return jsonify({'error': 'Mot de passe incorrect'}), 401

        # Vérifier le solde
        cursor.execute("SELECT solde FROM comptes WHERE user_id = %s", (user_id,))
        solde = cursor.fetchone()[0]
        
        if solde < montant:
            return jsonify({'error': 'Solde insuffisant'}), 400

        # Règles de détection de fraude
        is_fraud = 0
        proba_fraud = 0.0

        # Règle 1: Montant supérieur à 1000€
        if montant > 1000:
            is_fraud = 1
            proba_fraud = 0.7

        # Règle 2: Transaction utilisant tout le solde ou presque (>95%)
        if montant >= solde * 0.95:
            is_fraud = 1
            proba_fraud = max(proba_fraud, 0.8)  # On prend la plus haute probabilité

        # Insérer la transaction
        cursor.execute("""
            INSERT INTO transactions (user_id, destinataire_id, montant, is_fraud, statut)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, destinataire_id, montant, is_fraud, 'en_attente' if is_fraud else 'valide'))

        # Pour les transactions suspectes, on ne fait que l'insertion
        if is_fraud:
            conn.commit()
            return jsonify({
                'is_fraud': is_fraud,
                'proba_fraud': proba_fraud,
                'message': 'Transaction suspecte en attente de validation par l\'administrateur'
            })

        # Pour les transactions normales, on effectue le transfert
        try:
            # Débiter l'émetteur
            cursor.execute("""
                UPDATE comptes 
                SET solde = solde - %s 
                WHERE user_id = %s
            """, (montant, user_id))
            
            # Créditer le destinataire
            cursor.execute("""
                UPDATE comptes 
                SET solde = solde + %s 
                WHERE user_id = %s
            """, (montant, destinataire_id))
            
            conn.commit()
            return jsonify({
                'is_fraud': is_fraud,
                'proba_fraud': proba_fraud,
                'message': 'Transaction effectuée avec succès'
            })
        except Exception as e:
            conn.rollback()
            return jsonify({'error': f'Erreur lors du transfert: {str(e)}'}), 500

    except Exception as e:
        print(f"Erreur lors de la prédiction: {str(e)}")
        if conn:
            conn.rollback()
        return jsonify({'error': f'Erreur lors de la prédiction: {str(e)}'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route("/export_frauds", methods=["GET"])
@token_required
@admin_required
def export_frauds(current_user_id, role):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT t.id, u1.nom AS emetteur, u2.nom AS destinataire, t.montant, t.date, t.statut "
            "FROM transactions t "
            "JOIN utilisateurs u1 ON t.user_id = u1.id "
            "JOIN utilisateurs u2 ON t.destinataire_id = u2.id "
            "WHERE t.is_fraud = 1"
        )
        rows = cursor.fetchall()

        csv_file = "frauds_export.csv"
        with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["ID", "Émetteur", "Destinataire", "Montant", "Date", "Statut"])
            for row in rows:
                writer.writerow(row)

        print(f"Fraudes exportées dans {csv_file}")
        return send_file(csv_file, as_attachment=True)
    except Exception as e:
        print("Erreur lors de l'exportation des fraudes :", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/users/<int:user_id>", methods=["GET", "PUT"])
@token_required
def get_or_update_user(current_user_id, role, user_id):
    if request.method == "GET":
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, nom, email, role 
                FROM utilisateurs 
                WHERE id = %s
            """, (user_id,))
            user = cursor.fetchone()
            
            if not user:
                print(f"Utilisateur non trouvé : user_id={user_id}")
                return jsonify({"error": "Utilisateur non trouvé"}), 404
            
            return jsonify({
                "id": user[0],
                "nom": user[1],
                "email": user[2],
                "role": user[3]
            })
        except Exception as e:
            print("Erreur lors de la récupération de l'utilisateur :", str(e))
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()
    else:  # PUT
        # Vérifier que l'utilisateur modifie ses propres informations
        if current_user_id != user_id:
            return jsonify({"error": "Vous ne pouvez modifier que vos propres informations"}), 403

        try:
            data = request.get_json()
            print(f"Requête /users/{user_id} PUT reçue :", data)
            nom = data.get("nom")
            email = data.get("email")
            role = data.get("role")

            if not all([nom, email, role]):
                print("Erreur : Champs manquants")
                return jsonify({"error": "Tous les champs (nom, email, role) sont requis"}), 400

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE utilisateurs SET nom = %s, email = %s, role = %s WHERE id = %s",
                (nom, email, role, user_id)
            )
            if cursor.rowcount == 0:
                print(f"Utilisateur non trouvé : user_id={user_id}")
                return jsonify({"error": "Utilisateur non trouvé"}), 404
            conn.commit()
            print(f"Utilisateur mis à jour : user_id={user_id}")
            return jsonify({"message": "Utilisateur mis à jour avec succès"}), 200
        except Exception as e:
            conn.rollback()
            print("Erreur lors de la mise à jour de l'utilisateur :", str(e))
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

@app.route("/users/<int:user_id>/password", methods=["PUT"])
@token_required
def update_user_with_password(current_user_id, role, user_id):
    # Vérifier que l'utilisateur modifie ses propres informations
    if current_user_id != user_id:
        return jsonify({"error": "Vous ne pouvez modifier que votre propre mot de passe"}), 403

    try:
        data = request.get_json()
        print(f"Requête /users/{user_id}/password PUT reçue :", data)
        nom = data.get("nom")
        email = data.get("email")
        role = data.get("role")
        mot_de_passe = data.get("mot_de_passe")

        if not all([nom, email, role, mot_de_passe]):
            print("Erreur : Champs manquants")
            return jsonify({"error": "Tous les champs (nom, email, role, mot_de_passe) sont requis"}), 400

        # Hasher le nouveau mot de passe
        hashed_password = bcrypt.generate_password_hash(mot_de_passe).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE utilisateurs SET nom = %s, email = %s, role = %s, mot_de_passe = %s WHERE id = %s",
            (nom, email, role, hashed_password, user_id)
        )
        if cursor.rowcount == 0:
            print(f"Utilisateur non trouvé : user_id={user_id}")
            return jsonify({"error": "Utilisateur non trouvé"}), 404
        conn.commit()
        print(f"Utilisateur et mot de passe mis à jour : user_id={user_id}")
        return jsonify({"message": "Utilisateur et mot de passe mis à jour avec succès"}), 200
    except Exception as e:
        conn.rollback()
        print("Erreur lors de la mise à jour de l'utilisateur :", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/comptes/<int:user_id>", methods=["GET"])
@token_required
def get_solde(current_user_id, role, user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT solde FROM comptes WHERE user_id = %s", (user_id,))
        solde = cursor.fetchone()
        if solde is None:
            print(f"Compte non trouvé : user_id={user_id}")
            return jsonify({"error": "Compte non trouvé"}), 404
        return jsonify({"solde": solde[0]})
    except Exception as e:
        print("Erreur lors de la récupération du solde :", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/transactions/received/<int:user_id>", methods=["GET"])
@token_required
def get_received_transactions(current_user_id, role, user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.id, u1.nom AS emetteur, t.montant, t.date, t.is_fraud
            FROM transactions t
            JOIN utilisateurs u1 ON t.user_id = u1.id
            WHERE t.destinataire_id = %s
            ORDER BY t.date DESC
        """, (user_id,))
        transactions = cursor.fetchall()
        
        result = []
        for t in transactions:
            result.append({
                "id": t[0],
                "emetteur": t[1],
                "montant": float(t[2]),
                "date": t[3].strftime("%Y-%m-%d %H:%M:%S"),
                "statut": "Fraude suspectée" if t[4] else "Validée"
            })
        
        return jsonify({"transactions": result})
    except Exception as e:
        print("Erreur lors de la récupération des transactions reçues :", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/transactions/sent/<int:user_id>", methods=["GET"])
@token_required
def get_sent_transactions(current_user_id, role, user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.id, u2.nom AS destinataire, t.montant, t.date, t.is_fraud
            FROM transactions t
            JOIN utilisateurs u2 ON t.destinataire_id = u2.id
            WHERE t.user_id = %s
            ORDER BY t.date DESC
        """, (user_id,))
        transactions = cursor.fetchall()
        
        result = []
        for t in transactions:
            result.append({
                "id": t[0],
                "destinataire": t[1],
                "montant": float(t[2]),
                "date": t[3].strftime("%Y-%m-%d %H:%M:%S"),
                "statut": "Fraude suspectée" if t[4] else "Validée"
            })
        
        return jsonify({"transactions": result})
    except Exception as e:
        print("Erreur lors de la récupération des transactions envoyées :", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/verify_password", methods=["POST"])
@token_required
def verify_password(current_user_id, role):
    try:
        data = request.get_json()
        print(f"Requête /verify_password reçue pour l'utilisateur {current_user_id}")
        print(f"Données reçues : {data}")
        mot_de_passe = data.get("mot_de_passe")

        if not mot_de_passe:
            print("Erreur : Mot de passe manquant")
            return jsonify({"error": "Mot de passe requis"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT mot_de_passe, tentatives_mdp, derniere_tentative FROM utilisateurs WHERE id = %s", (current_user_id,))
            user = cursor.fetchone()
            if not user:
                print(f"Utilisateur non trouvé : user_id={current_user_id}")
                return jsonify({"error": "Utilisateur non trouvé"}), 404
            stored_password, tentatives, derniere_tentative = user
            print(f"Utilisateur trouvé : tentatives={tentatives}, derniere_tentative={derniere_tentative}")

            # Vérifier si l'utilisateur est bloqué
            if tentatives >= 3 and derniere_tentative:
                # Convertir derniere_tentative en datetime aware si ce n'est pas déjà le cas
                if derniere_tentative.tzinfo is None:
                    derniere_tentative = derniere_tentative.replace(tzinfo=timezone.utc)
                
                temps_ecoule = (datetime.now(timezone.utc) - derniere_tentative).total_seconds() / 60
                print(f"Temps écoulé depuis la dernière tentative : {temps_ecoule} minutes")
                if temps_ecoule < 5:  # 5 minutes de blocage
                    temps_restant = int(5 - temps_ecoule)
                    print(f"Utilisateur bloqué, temps restant : {temps_restant} minutes")
                    return jsonify({
                        "error": f"Trop de tentatives incorrectes. Veuillez réessayer dans {temps_restant} minutes."
                    }), 429
                else:
                    # Réinitialiser le compteur après 5 minutes
                    print("Réinitialisation du compteur de tentatives")
                    cursor.execute("UPDATE utilisateurs SET tentatives_mdp = 0 WHERE id = %s", (current_user_id,))
                    conn.commit()

            # Vérifier le mot de passe avec bcrypt
            if not bcrypt.check_password_hash(stored_password, mot_de_passe):
                print("Mot de passe incorrect")
                # Incrémenter le compteur de tentatives avec un datetime aware
                current_time = datetime.now(timezone.utc)
                cursor.execute("""
                    UPDATE utilisateurs 
                    SET tentatives_mdp = tentatives_mdp + 1,
                        derniere_tentative = %s
                    WHERE id = %s
                """, (current_time, current_user_id))
                conn.commit()
                
                # Vérifier si c'est la 3ème tentative
                if tentatives + 1 >= 3:
                    print("Trop de tentatives incorrectes")
                    return jsonify({
                        "error": "Trop de tentatives incorrectes. Veuillez réessayer dans 5 minutes."
                    }), 429
                else:
                    print(f"Tentatives restantes : {3 - (tentatives + 1)}")
                    return jsonify({
                        "error": "Mot de passe incorrect",
                        "tentatives_restantes": 3 - (tentatives + 1)
                    }), 401

            # Réinitialiser le compteur si le mot de passe est correct
            print("Mot de passe correct, réinitialisation du compteur")
            cursor.execute("UPDATE utilisateurs SET tentatives_mdp = 0 WHERE id = %s", (current_user_id,))
            conn.commit()

            return jsonify({"message": "Mot de passe correct"}), 200
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print("Erreur lors de la vérification du mot de passe :", str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/users", methods=["GET"])
@token_required
def get_users(current_user_id, role):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, nom, email, role 
            FROM utilisateurs 
            WHERE id != %s AND role != 'admin'
            ORDER BY nom
        """, (current_user_id,))
        users = cursor.fetchall()
        
        result = []
        for user in users:
            result.append({
                "id": user[0],
                "nom": user[1],
                "email": user[2],
                "role": user[3]
            })
        
        return jsonify({"users": result})
    except Exception as e:
        print("Erreur lors de la récupération des utilisateurs :", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/transactions/monthly/count/<int:user_id>", methods=["GET"])
@token_required
def get_monthly_transaction_count(current_user_id, role, user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Vérifier que l'utilisateur accède à ses propres informations
        if current_user_id != user_id and role != "admin":
            return jsonify({"error": "Accès non autorisé"}), 403
            
        # Requête pour compter les transactions du mois en cours
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM transactions 
            WHERE user_id = %s 
            AND MONTH(date) = MONTH(CURRENT_DATE()) 
            AND YEAR(date) = YEAR(CURRENT_DATE())
        """, (user_id,))
        
        result = cursor.fetchone()
        return jsonify({"count": result[0] if result else 0})
        
    except Exception as e:
        print("Erreur lors du comptage des transactions :", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/transactions/monthly/amount/<int:user_id>", methods=["GET"])
@token_required
def get_monthly_transaction_amount(current_user_id, role, user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Vérifier que l'utilisateur accède à ses propres informations
        if current_user_id != user_id and role != "admin":
            return jsonify({"error": "Accès non autorisé"}), 403
            
        # Requête pour calculer le montant total des transactions du mois en cours
        cursor.execute("""
            SELECT COALESCE(SUM(montant), 0) as total 
            FROM transactions 
            WHERE user_id = %s 
            AND MONTH(date) = MONTH(CURRENT_DATE()) 
            AND YEAR(date) = YEAR(CURRENT_DATE())
        """, (user_id,))
        
        result = cursor.fetchone()
        return jsonify({"amount": float(result[0]) if result else 0.0})
        
    except Exception as e:
        print("Erreur lors du calcul du montant total :", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/transactions/<int:transaction_id>/status", methods=["PUT"])
@token_required
@admin_required
def update_transaction_status(current_user_id, role, transaction_id):
    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({"error": "Status manquant"}), 400

        new_status = data['status']
        if new_status not in ['valide', 'bloquee']:
            return jsonify({"error": "Status invalide. Valeurs acceptées : 'valide' ou 'bloquee'"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Vérifier si la transaction existe et récupérer ses informations
            cursor.execute("""
                SELECT user_id, destinataire_id, montant, statut 
                FROM transactions 
                WHERE id = %s
            """, (transaction_id,))
            transaction = cursor.fetchone()
            
            if not transaction:
                return jsonify({"error": "Transaction non trouvée"}), 404

            user_id, destinataire_id, montant, current_status = transaction

            # Vérifier que la transaction est en attente
            if current_status != 'en_attente':
                return jsonify({"error": "Seules les transactions en attente peuvent être validées ou bloquées"}), 400

            # Mettre à jour le statut de la transaction
            cursor.execute("""
                UPDATE transactions 
                SET statut = %s 
                WHERE id = %s
            """, (new_status, transaction_id))

            # Traitement différent selon que la transaction est validée ou bloquée
            if new_status == 'valide':
                # Débiter l'émetteur
                cursor.execute("""
                    UPDATE comptes 
                    SET solde = solde - %s 
                    WHERE user_id = %s
                """, (montant, user_id))
                
                # Créditer le destinataire
                cursor.execute("""
                    UPDATE comptes 
                    SET solde = solde + %s 
                    WHERE user_id = %s
                """, (montant, destinataire_id))
            else:
                # Pour les transactions bloquées, on ne fait que l'insertion
                pass

            conn.commit()
            return jsonify({"message": f"Statut de la transaction mis à jour : {new_status}"}), 200

        except Exception as e:
            conn.rollback()
            print(f"Erreur lors de la mise à jour du statut : {str(e)}")
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Erreur lors de la mise à jour du statut : {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)