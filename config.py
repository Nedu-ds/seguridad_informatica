class Config(object):
    SECRET_KEY = 'MFRSTWBPG@PYTHN'

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://seguridad:InfTec.2020@localhost/users'
    SQLALCHEMY_TRACK_MODIFICATIONS = False