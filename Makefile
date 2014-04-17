.PHONY: start check-env createdb requirements requirements-ci lint lint-ci syncdb syncdb-ci migratedb migratedb-ci test test-ci deploy-dev deploy-stg deploy-prd

ARCHFLAGS := -Wno-error=unused-command-line-argument-hard-error-in-future

check-env:
ifndef VIRTUAL_ENV
	$(error VIRTUAL_ENV is undefined. perhaps you should activate a virtualenv..)
endif
ifeq ($(shell vagrant status | grep running),)
	$(eval VAGRANT_CMD += vagrant up)
else
	$(eval VAGRANT_CMD += vagrant provision)
endif
ifeq ($(shell vagrant plugin list | grep vagrant-fabric),)
	$(eval VAGRANT_PLUGIN_CMD += vagrant plugin install vagrant-fabric)
else
	$(eval VAGRANT_PLUGIN_CMD += echo vagrant-fabric already installed)
endif

start: createdb requirements lint syncdb migratedb
	python {{project_name}}/manage.py runserver 0.0.0.0:8000

createdb:
	createuser -s {{project_name}} || exit 0
	createdb {{project_name}} || exit 0
	createdb {{project_name}}_test || exit 0

requirements: check-env
	pip install --allow-unverified PIL -r requirements/local.txt

requirements-global:
ifndef VIRTUAL_ENV
	@sudo easy_install -U pip==1.5.4
	@sudo pip install virtualenv
	@sudo pip install virtualenvwrapper
else
	$(error run requirements-global from outside your virtualenv)
endif
	@echo "Add the following to ~/.bash_profile"
	@echo "export WORKON_HOME=$HOME/.virtualenvs"
	@echo "source /usr/local/bin/virtualenvwrapper.sh"
	@echo "then run source ~/.bash_profile"

requirements-local: check-env
	@ARCHFLAGS=$(ARCHFLAGS) pip install --allow-unverified PIL -r requirements/local_provision.txt

requirements-ci:
	pip install "pip>=1.5.2"
	pip install --allow-unverified PIL -r requirements/test.txt
	pip install awscli

vagrant-plugins:
	@$(QUIET) vagrant plugin uninstall vagrant-vbguest || exit 0
	@$(QUIET) $(VAGRANT_PLUGIN_CMD)

lint:
	pylint -E fabfile.py
	pep8 --show-pep8 --statistics --show-source --format=pylint --exclude=./venv/* --ignore E501,E401 .

lint-ci: lint
	pylint -d R0914,R0913,C0103,W1401,C0301,R0915,W0703,R0912,C0111,C0302,W0511,C0303,C0325 -f html fabfile.py > ${CIRCLE_ARTIFACTS}/pylint.html

syncdb:
	python ./{{project_name}}/manage.py syncdb --noinput

syncdb-ci:
	python ./{{project_name}}/manage.py syncdb --noinput --settings=settings.test

migratedb: syncdb
	python ./{{project_name}}/manage.py migrate --noinput

migratedb-ci:
	python ./{{project_name}}/manage.py migrate --noinput --settings=settings.test

test: createdb requirements syncdb migratedb lint
	{{project_name}}/manage.py test -v3 --settings=settings.test

test-ci:
	coverage run --source='./{{project_name}}/' {{project_name}}/manage.py test -v3 --settings=settings.test

deploy-dev: requirements-local vagrant-plugins
	@$(VAGRANT_CMD)

deploy-stg:
	./deploy/deploy_aws.sh ${STAGING_STACK_ID} ${STAGING_APP_ID}

deploy-prd:
	./deploy/deploy_aws.sh ${PRODUCTION_STACK_ID} ${PRODUCTION_APP_ID}

destroy-dev:
	@vagrant destroy
