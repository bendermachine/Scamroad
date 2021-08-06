#!/usr/bin/python
# -*- coding: utf-8 -*-
def warn(*args, **kwargs):
    pass


import ipaddress
from django.http import HttpResponse, JsonResponse
from django.db.models import Q
from .models import *
import warnings

warnings.warn = warn
import joblib
from lxml import html
from json import dump, loads
from requests import get
import json
from re import sub
from dateutil import parser as dateparser
from time import sleep
from django.http import HttpResponse
from django.shortcuts import render
import os
import pickle
import joblib
import whois
import datetime
from datetime import datetime
import csv
import urllib.request, sys, re
import xmltodict, json

# Create your views here.
def getServerStatus(request):
    return HttpResponse(request)


def error_404_view(request, exception):
    return render(request, "404.html")


def index(request):
    try:
        return render(request, "index.html")
    except:
        return render(request, "404.html")


warnings.warn = warn


def result(request):

    text = request.GET["url"]
    print(text)
    if not text.startswith("http"):
        return render(request, "404.html")


    elif text.startswith("https://www.google.com/search?q="):

        return render(
            request,
            "result.html",
            {
                "result": "Real-time analysis successfull",
                "f2": "Legtimate",
                "mal": True,
                "text": text,
                "name": "not found by google",
                "org": "not found by google",
                "add": "not found by google",
                "city": "not found by google",
                "state": "not found by google",
                "ziip": "not found by google",
                "country": "not found by google",
                "emails": "not found by google",
                "dom": "not found by google",
                "rank": "not found by google",
                "tags": "not found by google",
                "registrar": "Hidden For Privacy",
                "var13": "not found by google",
                "varab": "not found by google",
                "var11": "not found by google",
                "var10": "not found by google",
                "var5": "not found by google",
                "var4": "not found by google",
                "var3": "not found by google",
                "index": "dfgdfgfdg",
            },
        )

    elif text.startswith("https://www.google.com/search?q=") == False:

        if text.startswith("https://") or text.startswith("http://"):
            varab = "Not Applicable"  # больший индекс в дб алексы
            var13 = "Not Applicable"  # больший индекс в дб алексы
            var11 = "Not Applicable"  # проверяет сколько работает домен
            var10 = "Not Applicable"  # обнаруживает больше 2х перенаправлений
            var5 = "Not Applicable"  # обнаруживает префикс "-" в ссылке
            var4 = "Not Applicable"  # отвечат за множественные перенапраления
            var3 = "Not Applicable"  # обнаруживает "@" в ссылке

            if len(text) <= 9:
                return render(request, "404.html")
            aburl = -1
            digits = "0123456789"
            if len(text) <= 12:
                tiny_url = -1
            else:
                tiny_url = 1
            if len(text) > 54:
                url_len = -1
            else:
                url_len = 1

            k = text.count("//")
            if k > 3:
                url_depth = -1
            else:
                url_depth = 1
            if "-" in text:
                url_prefix = -1
            else:
                url_prefix = 1
            digit_start = -1
            if "@" in text:
                url_at_sign = -1
            else:
                url_at_sign = 1
            digits = "01234567890"
            if "https" in text:
                if text[8] in digits:
                    digit_start = 1
                https_domain = 1
            else:
                if text[7] in digits:
                    digit_start = 1
                https_domain = -1
            temp = text
            temp = temp[6:]
            k1 = temp.count("http")

            if k1 >= 1:
                redirection = -1
            else:
                redirection = 1

            url = text

            d = -1
            try:
                res = whois.whois(url)
            except:
                print("getaddrerrror DNE")
                d = 0
                name = "Not found in database"
                org = "Not found in database"
                add = "Not found in database"
                city = "Not found in database"
                state = "Not found in database"
                ziip = "Not found in database"
                country = "Not found in database"
                emails = "Not found in database"
                dom = "Not Found"
                registrar = "Not Found"
            if d != 0:
                try:
                    if len(res.creation_date) > 1:
                        a = res["creation_date"][0]
                        b = datetime.now()
                        c = b - a
                        d = c.days
                except:
                    a = res["creation_date"]
                    b = datetime.now()
                    c = b - a
                    d = c.days

            if d > 14:
                old_url = 1
                young_url = -1
                aburl = 1
            elif d <= 14:
                young_url = 1
                old_url = -1
                aburl = -1
                var11 = "Domain working less than a 2 weeks"

            try:
                ipaddress.ip_address(url)
                url_ip = 1
            except:
                url_ip = -1

            import urllib.request, sys, re
            import xmltodict, json

            try:
                xml = urllib.request.urlopen(
                    "http://data.alexa.com/data?cli=10&dat=s&url={}".format(text)
                ).read()

                result = xmltodict.parse(xml)

                data = json.dumps(result).replace("@", "")
                data_tojson = json.loads(data)
                url = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["URL"]
                rank = int(data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"])
                if rank <= 100000:
                    url_rank = 1
                else:
                    url_rank = -1
            except:
                url_rank = -1
                rank = 0

            filename = "phish_trainedv3.sav"

            loaded_model = joblib.load(filename)

            arg = loaded_model.predict(
                (
                    [
                        [
                            tiny_url,
                            url_len,
                            url_depth,
                            https_domain,
                            digit_start,
                            redirection,
                            young_url,
                            old_url,
                            url_rank,
                            url_ip,
                            url_at_sign,
                            url_prefix,
                        ]
                    ]
                )
            )

            url = text

            if d != 0:
                name = res.domain_name
                org = res.org
                add = res.address
                city = res.city
                state = res.state
                ziip = res.zipcode
                country = res.country
                emails = res.emails
                dom = res.domain_name
                registrar = res.registrar
            else:
                name = "Not found in database"
                org = "Not found in database"
                add = "Not found in database"
                city = "Not found in database"
                state = "Not found in database"
                ziip = "Not found in database"
                country = "Not found in database"
                emails = "Not found in database"
                dom = "Not Found"
                registrar = "Not Found"

            if dom == "Not Found" and rank == -1:
                arg[0] = -1
                # Phishing

            if arg[0] == 1:
                te = "Legal"
            else:
                te = "Phishing"
            if arg[0] == 1:
                mal = True
            else:
                mal = False

            # print (name,org,add,city,state,ziip,country,emails,dom)

            from json.encoder import JSONEncoder

            final_entity = {"predicted_argument": [int(arg[0])]}
            # directly called encode method of JSON
            # print (JSONEncoder().encode(final_entity))
            obj = Url()
            obj.result = te
            # print (dom,rank)

            tags = [name, org, state, add, city, ziip, country, emails, dom, rank]
            #
            # tags = list(filter(lambda x: x != "Not Found", tags))
            # tags.append(text)
            # obj.link = text
            # obj.add = add
            # obj.state = state
            # obj.city = city
            # obj.country = country
            # obj.emails = emails
            # obj.dom = dom
            # obj.org = org
            # obj.rank = rank
            # obj.registrar = registrar
            # obj.save()
            # 



            if add != None:
                if add and len(add) == 1:
                    add = add.replace(",", "")
                elif len(add) > 1:
                    add = "".join(add)

            name = "".join(name)
            if emails != None:
                emails = "".join(emails)
            if org != None:
                org = org.replace(",", "")
            dom = "".join(dom)
            if registrar:
                registrar = registrar.replace(",", "")

            with open("static//dataset.csv", "a") as res:
                writer = csv.writer(res)
                s = "{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
                    text,
                    te,
                    (name),
                    org,
                    add,
                    city,
                    state,
                    ziip,
                    country,
                    emails,
                    str(dom),
                    rank,
                    str(registrar),
                )
                res.write(s)

            return render(
                request,
                "result.html",
                {
                    "result": "Real-time analysis successfull",
                    "f2": te,
                    "mal": mal,
                    "text": text,
                    "name": name,
                    "org": org,
                    "add": add,
                    "city": city,
                    "state": state,
                    "ziip": ziip,
                    "country": country,
                    "emails": emails,
                    "dom": dom,
                    "rank": rank,
                    "registrar": registrar,
                    "tags": tags,
                    "var13": var13,
                    "varab": varab,
                    "var11": var11,
                    "var10": var10,
                    "var5": var5,
                    "var4": var4,
                    "var3": var3,
                },
            )

    else:
        return render(request, "404.html")

def getdataset(request):
    try:
        return render(request, "getdataset.html")
    except:
        return render(request, "404.html")
