#!/usr/bin/python3
import datetime
import random
import sys
import math
from string import ascii_lowercase as alphabet
from multiprocessing import Pool

word_list = open("/usr/share/dict/words").read().splitlines()

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

def rand_category(num_cats):
    category = random.randrange(num_cats)

    return "category" + str(category)

def rand_date():
    start_date = datetime.date(2020, 1, 1)
    random_number_of_days = random.randrange(365)
    random_date = start_date + datetime.timedelta(days=random_number_of_days)

    return str(random_date.month) + "/" + str(random_date.day) + "/" + str(random_date.year)

def rand_person():
    person = random.randrange(1000)
    return "person" + str(person)

def rand_item(num_items):
    item = random.randrange(num_items)
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

def print_item(item_number, num_cats):
    line = ""
    item_name = "item" + str(item_number)
    line += "<item id=\"" + item_name + "\">\n"

    line += "<location>" + rand_word() + "</location>\n"
    line += "<quantity>1</quantity>\n"
    line += "<name>" + rand_word() + rand_word() + rand_word() + "</name>\n"
    line += "<payment>" + rand_word() + "</payment>\n"

    line += "<description>\n"
    line += "<parlist>\n"
    line += "<listitem>\n"
    line += "<text>\n"
    line += rand_string(30, 60) + "\n"
    line += "</text>\n"
    line += "</listitem>\n"
    line += "</parlist>\n"
    line += "</description>\n"

    line += "<shipping>" + rand_string(5, 10) + "</shipping>\n"

    for i in range(random.randrange(2, 5)):
        line += "<incategory category=\"" + rand_category(num_cats) + "\"/>\n"

    line += "<mailbox>\n"
    line += "<mail>\n"
    line += "<from>" + rand_string(2, 3) + "mailto:" + rand_word()[:-1] + "@" + rand_word()[:-1] + ".com</from>\n"
    line += "<to>" + rand_string(2, 3) + "mailto:" + rand_word()[:-1] + "@" + rand_word()[:-1] + ".com</to>\n"
    line += "<date>" + rand_date() + "</date>\n"
    line += "<text>\n"
    line += rand_string(30, 60) + "\n"
    line += "</text>\n"
    line += "</mail>\n"
    line += "</mailbox>\n"

    line += "</item>\n"
    return line

def print_items(start, num_items, num_cats):
    print("item " + str(start))

    line = ""
    for i in range(start, start + num_items):
        line += print_item(i, num_cats)

    return line

def print_region(region, start_item, num_items, num_cats):
    print("region " + region)
    print(str(start_item) + " " + str(start_item + num_items))
    line = ""

    line += "<" + region + ">\n"

    # Generate the inputs to the pool for the items
    pool_params = []
    pool_size = 1000
    item_end = start_item + num_items
    for i in range(start_item, item_end, pool_size):
        if i + pool_size > item_end:
            pool_size = item_end - i
        pool_params.append((i, pool_size, num_cats))
    # Generate the items
    with Pool() as p:
        results = p.starmap(print_items, pool_params)
        for item in results:
            line += item

    line += "</" + region + ">\n"

    return line

def print_categories(start, num_categories):
    print("caregory " + str(start))

    line = "<categories>\n"
    for i in range(start, start + num_categories):
        line += "<category id=\"category" + str(i) + "\">\n"
        line += "<name>" + rand_string(2, 3) + "</name>\n"
        line += "<description>\n"
        line += "<text>\n"
        line += rand_string(30, 60) + "\n"
        line += "</text>\n"
        line += "</description>\n"
        line += "</category>\n"
    line += "</categories>\n"

    return line

def print_closed_auctions(start, num_auctions, num_items):
    print("auction " + str(start))

    line = "<closed_auctions>\n"
    for i in range(start, start + num_auctions):
        line += "<closed_auction>\n"
        line += "<seller person=\"" + rand_person() + "\"/>\n"
        line += "<buyer person=\"" + rand_person() + "\"/>\n"
        line += "<itemref item=\"" + rand_item(num_items) + "\"/>\n"
        line += "<price>" + str(random.randrange(0, 1000)) + "</price>\n"
        line += "<date>" + rand_date() + "</date>\n"
        line += "<quantity>1</quantity>\n"
        line += "<type>" + rand_word() + "</type>\n"
        line += "<annotation>\n"
        line += "<author person=\"" + rand_person() + "\"/>\n"
        line += "<description>\n"
        line += "<text>\n"
        line += rand_string(25, 50) + "\n"
        line += "</text>\n"
        line += "</description>\n"
        line += "<happiness>" + str(random.randrange(0, 10)) + "</happiness>\n"
        line += "</annotation>\n"
        line += "</closed_auction>\n"
    line += "</closed_auctions>\n"

    return line

if __name__ == '__main__':
    if len(sys.argv) < 3:
        sys.stderr.write("Usage: ./rand_xalanc_input.py <size> <output file>\n")
        sys.exit()

    xml_header = """<?xml version="1.0" standalone="yes"?>
        <site xmlns="http://www.schemaTest.org/100mb"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n"""

    size = int(sys.argv[1])
    filename = sys.argv[2]
    f = open(filename, "w")

    regions = ["africa", "asia", "australia", "europe", "namerica", "samerica"]
    num_items = size * 750
    items_in_region = int(num_items / len(regions))
    num_categories = int(math.sqrt(num_items))
    num_auctions = size * 50

    f.write(xml_header)

    # Generate the regions
    f.write("<regions>\n")
    for (i, region) in enumerate(regions):
        region_text = print_region(region, i * items_in_region, items_in_region, num_categories)
        f.write(region_text)
    f.write("</regions>\n")

    # Generate the inputs to the pool for the categories
    pool_params = []
    pool_size = 100
    for i in range(0, num_categories, pool_size):
        if i + pool_size > num_categories:
            pool_size = num_categories - i
        pool_params.append((i, pool_size))
    # Generate the categories
    with Pool() as p:
        results = p.starmap(print_categories, pool_params)
        for category in results:
            f.write(category)

    # Generate the inputs for the closed auctions
    pool_params = []
    pool_size = 10000
    for i in range(0, num_auctions, pool_size):
        if i + pool_size > num_auctions:
            pool_size = num_auctions - i
        pool_params.append((i, pool_size, num_items))
    # Generate the auctions
    with Pool() as p:
        results = p.starmap(print_closed_auctions, pool_params)
        count = 0
        for auction in results:
            f.write(auction)

            count = count + 1
            if count % 100 == 0:
                print("Writing " + str(count))

    f.write("</site>\n")
    f.close()
