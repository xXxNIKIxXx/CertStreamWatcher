from services.dashboard.app import create_app

from gevent import monkey
monkey.patch_all()

app = create_app()
