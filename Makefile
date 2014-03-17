.PHONY: start createdb requirements requirements-ci lint lint-ci syncdb syncdb-ci migratedb migratedb-ci test test-ci deploy-stg deploy-prd

start: createdb requirements lint syncdb migratedb
	python project_name/manage.py runserver 0.0.0.0:8000

createdb:
	createuser -d skeleton || exit 0
	createdb skeleton || exit 0
	createdb skeleton_test || exit 0

requirements:
	pip install --allow-unverified PIL -r requirements/local.txt

requirements-ci:
	pip install --allow-unverified PIL -r requirements/test.txt

lint:
	pylint -E fabfile.py
	pep8 --show-pep8 --statistics --show-source --format=pylint --exclude=./venv/* --ignore E501,E401 .

lint-ci: lint
	pylint -d R0914,R0913,C0103,W1401,C0301,R0915,W0703,R0912,C0111,C0302,W0511,C0303,C0325 -f html fabfile.py > ${CIRCLE_ARTIFACTS}/pylint.html

syncdb:
	python ./project_name/manage.py syncdb --noinput

syncdb-ci:
	python ./project_name/manage.py syncdb --noinput --settings=settings.test

migratedb: syncdb
	python ./project_name/manage.py migrate --noinput

migratedb-ci:
	python ./project_name/manage.py migrate --noinput --settings=settings.test

test: createdb requirements syncdb migratedb lint
	project_name/manage.py test -v3 --settings=settings.test 

test-ci:
	coverage run --source='./project_name/' project_name/manage.py test -v3 --settings=settings.test

deploy-stg:
	./deploy/deploy_aws.sh $STAGING_STACK_ID $STAGING_APP_ID

deploy-prd:
	./deploy/deploy_aws.sh $PRODUCTION_STACK_ID $PRODUCTION_APP_ID
