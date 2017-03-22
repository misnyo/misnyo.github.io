---
layout: blog
title: blog
---

<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ site.url }}{{ post.url }}">{{ post.title }}<span class="entry-date"> <time datetime="{{ post.date | date_to_xmlschema }}" itemprop="datePublished">{{ post.date | date: "%B %d, %Y" }}</time> </span></a>
      <p>{{ post.excerpt }}</p>
    </li>
  {% endfor %}
</ul>
