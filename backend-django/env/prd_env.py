# ************** 默认数据库 配置  ************** #
# ================================================= #
# 数据库类型 MYSQL/SQLSERVER/SQLITE3/POSTGRESQL
import os

DATABASE_TYPE = "POSTGRESQL"
# 数据库地址
DATABASE_HOST = "172.18.0.3"
# 数据库端口
DATABASE_PORT = 5432
# 数据库用户名
DATABASE_USER = os.environ.get('DEV_DB_USER', "test")
# 数据库密码
DATABASE_PASSWORD = os.environ.get('DEV_DB_PASSWORD', "123")
# 数据库名
DATABASE_NAME = ""

# ================================================= #
# ******** redis配置 *********** #
# ================================================= #
REDIS_PASSWORD = ''
REDIS_HOST = '172.18.0.4'
REDIS_DB = '4'
REDIS_URL = f'redis://:{REDIS_PASSWORD or ""}@{REDIS_HOST}:6379'


# # ================================================= #
# # ******************** JWT 配置 ***************** #
# # ================================================= #

# JWT 密钥从环境变量读取
JWT_ACCESS_SECRET_KEY = os.environ.get(
    'JWT_ACCESS_SECRET_KEY',
    'default-access-secret-key-change-in-production'
)
JWT_REFRESH_SECRET_KEY = os.environ.get(
    'JWT_REFRESH_SECRET_KEY',
    'default-refresh-secret-key-change-in-production'
)


# ================================================= #
# ******** 其他配置 *********** #
# ================================================= #
IS_DEMO = False