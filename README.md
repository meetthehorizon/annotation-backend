backend for annotation project

- install postgresql, python-3.10, pgadmin4
- create a virtual environment `venv`, activate it and install dependencies using `requirements.txt`
- install [prettier](https://marketplace.visualstudio.com/items?itemName=esbenp.prettier-vscode) extension on vs code
- create a postgresql database `annotationdb` create a `role` with a `password`
- copy `.env.example` to `.env` and update relevant fields
- run migrations using `flask db upgrade`
- run the server using `python run.py`
