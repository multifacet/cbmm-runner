#!/usr/bin/python3
import datetime
import random
import sys
from string import ascii_lowercase as alphabet

xml_header = """<?xml version="1.0" standalone="yes"?>
    <site xmlns="http://www.schemaTest.org/100mb"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">"""

word_list = open("/usr/share/dict/words").read().splitlines()

item_count = 0
category_count = 1

def rand_word():
    word = random.choice(word_list) + " "
    # Xalanc doesn't like the & symbol in words
    word = word.replace("&", "")
    return word + " "

def rand_string(min_words, max_words):
    string = ""
    for i in range(random.randrange(min_words, max_words)):
        string += rand_word()

    return string

def rand_category():
    global category_count

    category = random.randrange(category_count + 1)
    if category == category_count:
        category_count += 1

    return "category" + str(category)

def rand_date():
    start_date = datetime.date(2020, 1, 1)
    random_number_of_days = random.randrange(365)
    random_date = start_date + datetime.timedelta(days=random_number_of_days)

    return str(random_date.month) + "/" + str(random_date.day) + "/" + str(random_date.year)

def rand_person():
    person = random.randrange(1000)
    return "person" + str(person)

def rand_item():
    item = random.randrange(item_count)
    return "item" + str(item)

def number_to_letters(i):
    letters = ""
    if i == 0:
        return "a"
    while i >= 0:
        letter = alphabet[i % 26]
        i = int(i / 26) - 1
        letters = letter + letters

    return letters

def print_item():
    global item_count

    item_name = "item" + str(item_count)
    print("<item id=\"" + item_name + "\">")

    print("<location>" + rand_word() + "</location>")
    print("<quantity>1</quantity>")
    print("<name>" + rand_word() + rand_word() + rand_word() + "</name>")
    print("<payment>" + rand_word() + "</payment>")

    print("<description>")
    print("<parlist>")
    print("<listitem>")
    print("<text>")
    print(rand_string(30, 60))
    print("</text>")
    print("</listitem>")
    print("</parlist>")
    print("</description>")

    print("<shipping>" + rand_string(5, 10) + "</shipping>")

    for i in range(random.randrange(2, 5)):
        print("<incategory category=\"" + rand_category() + "\"/>")

    print("<mailbox>")
    print("<mail>")
    print("<from>" + rand_string(2, 3) + "mailto:" + rand_word()[:-1] + "@" + rand_word()[:-1] + ".com</from>")
    print("<to>" + rand_string(2, 3) + "mailto:" + rand_word()[:-1] + "@" + rand_word()[:-1] + ".com</to>")
    print("<date>" + rand_date() + "</date>")
    print("<text>")
    print(rand_string(30, 60))
    print("</text>")
    print("</mail>")
    print("</mailbox>")

    print("</item>")
    item_count += 1

def print_regions(num_regions):
    print("<regions>")
    for i in range(num_regions):
        region = "region" + number_to_letters(i)
        print("<" + region + ">")
        for j in range(750):
            print_item()

        print("</" + region + ">")

    print("</regions>")

def print_categories():
    print("<categories>")
    for i in range(category_count):
        print("<category id=\"category" + str(i) + "\">")
        print("<name>" + rand_string(2, 3) + "</name>")
        print("<description>")
        print("<text>")
        print(rand_string(30, 60))
        print("</text>")
        print("</description>")
        print("</category>")
    print("</categories>")

def print_closed_auctions(num_auctions):
    print("<closed_auctions>")
    for i in range(num_auctions):
        print("<closed_auction>")
        print("<seller person=\"" + rand_person() + "\"/>")
        print("<buyer person=\"" + rand_person() + "\"/>")
        print("<itemref item=\"" + rand_item() + "\"/>")
        print("<price>" + str(random.randrange(0, 1000)) + "</price>")
        print("<date>" + rand_date() + "</date>")
        print("<quantity>1</quantity>")
        print("<type>" + rand_word() + "</type>")
        print("<annotation>")
        print("<author person=\"" + rand_person() + "\"/>")
        print("<description>")
        print("<text>")
        print(rand_string(25, 50))
        print("</text>")
        print("</description>")
        print("<happiness>" + str(random.randrange(0, 10)) + "</happiness>")
        print("</annotation>")
        print("</closed_auction>")
    print("</closed_auctions>")

if len(sys.argv) < 2:
    sys.stderr.write("An argument specifying output size is required\n")
    sys.exit()

size = int(sys.argv[1])

print(xml_header)
print_regions(size)
print_categories()
print_closed_auctions(size * 50)
print("</site>")
