{% extends "base.tpl" %}

{% title %}{_ Login _}{% endtitle %}

{% block html_head_extra %}
{% lib
    "css/z.icons.css"
    "css/logon.css"
    "font-awesome/css/font-awesome.min.css"
%}
{% endblock %}

{% block content_area %}
    {% if not m.acl.user or not m.auth_service.is_valid_request %}

        {% wire action={redirect back} %}

    {% else %}

        <div class="text-center">
            <h1>{_ Sign in _}</h1>
        </div>

        <p class="text-center">
            <br>
            <br>
            {% if m.auth_service.remote_site as remote_site %}
                {_ You are signed in, you can now continue to _} <b>{{ remote_site }}</b><br>
            {% else %}
                {_ You are signed in, you can now continue to your site. _}<br>
            {% endif %}

            <br>
            <br>

            <a href="#" id="{{ #ready }}" class="btn btn-lg btn-success">{_ Continue _}</a>

            <img style="display:none" id="{{ #spinner}}" src="/lib/images/spinner.gif" height="16" width="16">
        </p>

        {% wire id=#ready
            action={hide target=#ready}
            action={fade_in target=#spinner}
            postback={auth_service_logon_done request_token=q.token}
            delegate=`mod_auth_service`
        %}

    {% endif %}

{% endblock %}

