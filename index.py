##
## ===========================================
## ============= API MedicalApp ==============
## ===========================================
##
## Autores:
##   Francisco Rodrigues
##   Pedro Sousa
##

from flask import Flask, jsonify, request
import logging, time, psycopg2, jwt, json
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)   

app.config['SECRET_KEY'] = 'it\xb5u\xc3\xaf\xc1Q\xb9\n\x92W\tB\xe4\xfe__\x87\x8c}\xe9\x1e\xb8\x0f'

NOT_FOUND_CODE = 400
OK_CODE = 200
SUCCESS_CODE = 201
BAD_REQUEST_CODE = 400
UNAUTHORIZED_CODE = 401
FORBIDDEN_CODE = 403
NOT_FOUND = 404
SERVER_ERROR = 500

  
##########################################################
## HOME
##########################################################
@app.route('/', methods = ["GET"])
def home():
    return "Bem vindo à API da MedicalApp!"


##########################################################
## TOKEN INTERCEPTOR
##########################################################
def auth_user(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        content = request.get_json()
        if content is None or "u_token" not in content or not content["u_token"]:
            return jsonify({'Erro': 'Token está em falta!', 'Code': UNAUTHORIZED_CODE})

        try:
            decoded_token = jwt.decode(content['u_token'], app.config['SECRET_KEY'], algorithms=["HS256"])
            if(decoded_token["expiration"] < str(datetime.utcnow())):
                return jsonify({"Erro": "O Token expirou!", "Code": NOT_FOUND_CODE})

        except Exception as e:
            print(e)
            return jsonify({'Erro': 'Token inválido'}), FORBIDDEN_CODE
        
        return func(*args, **kwargs)
    return decorated
  

##########################################################
## REGISTO DE UTILIZADOR
##########################################################
@app.route("/registar_utilizador", methods=['POST'])
def registar_utilizador():
    content = request.get_json()

    #Verificar se foram recebidos os campos
    if "u_nome" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Message": 'Campo "nome" em falta!'})
    if "u_password" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Message": 'Campo "password" em falta!'})
    
    verifica_user = """
                SELECT *
                FROM utilizador
                WHERE u_nome = %s;
                """
    
    values = [content["u_nome"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(verifica_user, values)
                rows = cursor.fetchall()
                if len(rows) > 0:
                    return jsonify({"Code": NOT_FOUND_CODE, "Erro": "O utilizador com esse nome já existe"})
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})             

    get_user_info = """
                INSERT INTO utilizador(u_nome, u_password) 
                VALUES(%s, crypt(%s, gen_salt('bf')));
                """

    values = [content["u_nome"], content["u_password"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    finally:
        conn.commit()
        conn.close()
    return {'Code': OK_CODE, 'Message': 'Utilizador registado com sucesso!'}


##########################################################
## LOGIN
##########################################################
@app.route("/login", methods=['POST'])
def login():
    content = request.get_json()

    #Verificar se foram recebidos os campos
    if "u_nome" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Message": 'Campo "nome" em falta!'})
    if "u_password" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Message": 'Campo "password" em falta!'})

    get_user_info = """
                SELECT *
                FROM utilizador
                WHERE u_nome = %s AND u_password = crypt(%s, u_password);
                """

    values = [content["u_nome"], content["u_password"]]

    tokenUpdate = """
                    UPDATE utilizador
                    SET u_token = %s
                    WHERE u_id = %s
                """

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
                if rows:
                    token = jwt.encode({
                        'id': rows[0][0],
                        'expiration': str(datetime.utcnow() + timedelta(hours=1))
                    }, app.config['SECRET_KEY'])
                    addToken = [token, rows[0][0]]
                    cursor.execute(tokenUpdate, addToken)
                else:
                    return jsonify({'Code': BAD_REQUEST_CODE, 'Message': 'Credencias erradas!'})
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Utilizador não encontrado"})
    finally:
        conn.commit()
        conn.close()
    return {"Code": OK_CODE, 'Token': token}


##########################################################
## LOGOUT
##########################################################
@app.route("/logout", methods=['PUT'])
@auth_user
def logout():
    content = request.get_json()
    decoded_token = jwt.decode(content['u_token'], app.config['SECRET_KEY'], algorithms=["HS256"])
    
    removeToken = """
                    UPDATE utilizador
                    SET u_token = NULL
                    WHERE u_id = %s
                """
    
    values = [decoded_token["id"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(removeToken, values)
    except (Exception, psycopg2.DatabaseError) as error:
         return jsonify({'Code': NOT_FOUND_CODE, 'Message': str(error)})
    finally:
        conn.commit()
        conn.close()
    return jsonify({"Code": OK_CODE, 'Message': 'Utilizador fez logout com sucesso!'})


##########################################################
## ADICIONAR MEDICAMENTO
##########################################################
@app.route("/adicionar_medicamento", methods=['POST'])
@auth_user
def adicionar_medicamento():
    content = request.get_json()
    decoded_token = jwt.decode(content['u_token'], app.config['SECRET_KEY'], algorithms=["HS256"])
    
    params = ["m_nome", "m_dosagem", "m_forma_farmaceutica", "m_posologia", "m_quantidade", "m_duracao", "m_data_inicio", "m_hora1", "m_hora2", "m_hora3", "m_hora4"]
    if not all(param in content for param in params):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})

    verifica_existencia_medicamento = """
                                        SELECT 1 FROM medicamento
                                        WHERE u_id = %s AND m_nome = %s AND m_data_inicio = %s
                                    """

    values = [decoded_token["id"], content["m_nome"], content["m_data_inicio"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(verifica_existencia_medicamento, values)
                if cursor.fetchone():
                    return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Já existe um medicamento com o mesmo nome e data de início"})
                
                insert_medicamento = """
                                        INSERT INTO medicamento(u_id, m_nome, m_dosagem, m_forma_farmaceutica, m_posologia, m_quantidade, m_duracao, m_data_inicio, m_hora1, m_hora2, m_hora3, m_hora4)
                                        VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s ,%s);
                                    """
                values = [decoded_token["id"], content["m_nome"], content["m_dosagem"], content["m_forma_farmaceutica"], content["m_posologia"], content["m_quantidade"], content["m_duracao"], content["m_data_inicio"], content["m_hora1"], content["m_hora2"], content["m_hora3"], content["m_hora4"]]
                cursor.execute(insert_medicamento, values)
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    finally:
        conn.commit()
        conn.close()
    return {'Code': OK_CODE, 'Message': 'Medicamento adicionado com sucesso!'}


##########################################################
## OBTER MEDICAMENTOS
##########################################################
@app.route("/listar_medicamentos", methods=['GET'])
@auth_user
def listar_medicamentos():
    content = request.get_json()
    decoded_token = jwt.decode(content['u_token'], app.config['SECRET_KEY'], algorithms=["HS256"])

    medicamentos = """
                    SELECT *
                    FROM medicamento
                    WHERE u_id = %s
                    ORDER By m_data_inicio DESC
                """
    
    values = [decoded_token["id"]]
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(medicamentos, values)
                rows = cursor.fetchall()
                if rows:
                    medicamentos = []
                    for row in rows:
                        medicamentos.append({
                            "m_id": row[0],
                            "m_nome": row[2],
                            "m_dosagem": row[3],
                            "m_forma_farmaceutica": row[4],
                            "m_posologia": row[5],
                            "m_quantidade": row[6],
                            "m_duracao": row[7],
                            "m_data_inicio": row[8],
                            "m_hora1": row[9],
                            "m_hora2": row[10],
                            "m_hora3": row[11],
                            "m_hora4": row[12]
                        })
                    return jsonify({"Code": OK_CODE, "Medicamentos": medicamentos})
                else:
                    return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Este utilizador não tem medicamentos registados"})
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    finally:
        conn.commit()
        conn.close()


##########################################################
## INFORMACAO DE UM MEDICAMENTO
##########################################################
@app.route("/informacao_medicamento/<int:m_id>", methods=['GET'])
@auth_user
def informacao_medicamento(m_id):
    content = request.get_json()
    decoded_token = jwt.decode(content['u_token'], app.config['SECRET_KEY'], algorithms=["HS256"])

    medicamento_query = """
                        SELECT *
                        FROM medicamento
                        WHERE u_id = %s AND m_id = %s
                    """

    values = [decoded_token["id"], m_id]
    
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(medicamento_query, values)
                rows = cursor.fetchall()
                if rows:
                    medicamento = [{
                        "m_id": row[0],
                        "m_nome": row[2],
                        "m_dosagem": row[3],
                        "m_forma_farmaceutica": row[4],
                        "m_posologia": row[5],
                        "m_quantidade": row[6],
                        "m_duracao": row[7],
                        "m_data_inicio": row[8],
                        "m_hora1": row[9],
                        "m_hora2": row[10],
                        "m_hora3": row[11],
                        "m_hora4": row[12]
                    } for row in rows]
                    
                    return jsonify({"Code": OK_CODE, "Medicamento": medicamento})
                else:
                    return jsonify({"Code": NOT_FOUND_CODE, "Erro": "O medicamento com esse id não existe!"})
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    finally:
        conn.commit()
        conn.close()


##########################################################
## EDITAR INFO MEDICAMENTO
##########################################################
@app.route("/editar_medicamento/<int:m_id>", methods=['PUT'])
@auth_user
def editar_medicamento(m_id):
    content = request.get_json()
    decoded_token = jwt.decode(content['u_token'], app.config['SECRET_KEY'], algorithms=["HS256"])

    params = ["m_nome", "m_dosagem", "m_forma_farmaceutica", "m_posologia", "m_quantidade", "m_duracao", "m_data_inicio", "m_hora1", "m_hora2", "m_hora3", "m_hora4"]
    if not all(param in content for param in params):
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})

    verifica_existencia_medicamento = """
                                        SELECT 1 FROM medicamento
                                        WHERE u_id = %s AND m_id != %s AND m_nome = %s AND m_data_inicio = %s
                                    """

    values_check_existence = [decoded_token["id"], m_id, content["m_nome"], content["m_data_inicio"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(verifica_existencia_medicamento, values_check_existence)
                if cursor.fetchone():
                    return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Já existe um medicamento com o mesmo nome e data de início"})
                
                update_medicamento = """
                                    UPDATE medicamento
                                    SET m_nome = %s, m_dosagem = %s, m_forma_farmaceutica = %s, m_posologia = %s, m_quantidade = %s, m_duracao = %s, m_data_inicio = %s, m_hora1 = %s, m_hora2 = %s, m_hora3 = %s, m_hora4 = %s
                                    WHERE m_id = %s
                                """
                values_update_medicamento = [content["m_nome"], content["m_dosagem"], content["m_forma_farmaceutica"], content["m_posologia"], content["m_quantidade"], content["m_duracao"], content["m_data_inicio"], content["m_hora1"], content["m_hora2"], content["m_hora3"], content["m_hora4"], m_id]
                cursor.execute(update_medicamento, values_update_medicamento)
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": str(error)})
    finally:
        conn.commit()
        conn.close()
    return {'Code': OK_CODE, 'Message': 'Medicamento editado com sucesso!'}


##########################################################
## ELIMINAR MEDICAMENTO
##########################################################
@app.route("/eliminar_medicamento/<int:m_id>", methods=['DELETE'])
@auth_user
def eliminar_medicamento(m_id):
    content = request.get_json()
    decoded_token = jwt.decode(content['u_token'], app.config['SECRET_KEY'], algorithms=["HS256"])

    verifica_existencia_medicamento = """
                                        SELECT 1 FROM medicamento
                                        WHERE u_id = %s AND m_id = %s
                                    """

    values_check_existence = [decoded_token["id"], m_id]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(verifica_existencia_medicamento, values_check_existence)
                if not cursor.fetchone():
                    return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Não existe nenhum medicamento com esse id"})
                
                medicamento_query = """
                                    DELETE FROM medicamento
                                    WHERE u_id = %s AND m_id = %s
                                """
                values_delete_medicamento = [decoded_token["id"], m_id]
                cursor.execute(medicamento_query, values_delete_medicamento)
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": str(error)})
    finally:
        conn.commit()
        conn.close()
    
    return {'Code': OK_CODE, 'Message': 'Medicamento eliminado com sucesso!'}


##########################################################
## PERFIL DO UTILIZADOR
##########################################################
@app.route("/perfil", methods=['GET'])
@auth_user
def perfil():
    content = request.get_json()
    decoded_token = jwt.decode(content['u_token'], app.config['SECRET_KEY'], algorithms=["HS256"])

    get_user_info_query = """
                        SELECT u_id, u_nome
                        FROM utilizador
                        WHERE u_id = %s
                    """

    values = [decoded_token["id"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info_query, values)
                rows = cursor.fetchall()
                if rows:
                    utilizador_info = {
                        "u_id": rows[0][0],
                        "u_nome": rows[0][1]
                    }
                    return jsonify({"Code": OK_CODE, "Utilizador": utilizador_info})
                else:
                    return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Utilizador não encontrado!"})
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    finally:
        conn.commit()
        conn.close()


##########################################################
## DATABASE ACCESS
##########################################################
def db_connection():
    DATABASE_URL = 'postgresql://a2019131922:a2019131922@aid.estgoh.ipc.pt/db2019131922'
    db = psycopg2.connect(DATABASE_URL)
    return db


if __name__ == "__main__":
    app.run(port=5000, debug=True, threaded=True)