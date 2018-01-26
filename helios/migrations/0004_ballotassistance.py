# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import helios.datatypes


class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0003_auto_20160507_1948'),
    ]

    operations = [
        migrations.CreateModel(
            name='BallotAssistance',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uuid', models.CharField(max_length=50, null=True)),
                ('session', models.CharField(max_length=50, null=True)),
                ('cast_codes', models.CharField(max_length=50, null=True)),
                ('vote_code', models.CharField(max_length=50, null=True)),
                ('qr_session', models.CharField(max_length=50, null=True)),
                ('election', models.ForeignKey(to='helios.Election')),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model, helios.datatypes.LDObjectContainer),
        ),
    ]
