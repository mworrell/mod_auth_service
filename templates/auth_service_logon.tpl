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
    {% if m.auth_service.is_valid_request %}

        {% if m.acl.user %}

            {% wire action={redirect dispatch=`logoff` p=m.req.raw_path} %}

        {% elseif m.auth_service.is_valid_request %}

            <div class="text-center">
                <h1>{_ Sign in _}</h1>
            </div>

            <div id="auth-service-logon">

                <p class="text-center">
                    {% if m.auth_service.remote_site as remote_site %}
                        {_ After signing in we redirect to _} <b>{{ remote_site }}</b><br>
                    {% else %}
                        {_ After signing in we redirect to your site. _}<br>
                    {% endif %}
                </p>

                <p class="text-center text-muted">
                    <span class="icon-info-sign"></span> {_ You need to authenticate, even if you were previously signed in. _}
                </p>

                {% include "_logon_box.tpl"
                    form_title_tpl=""
                    form_extra_tpl=""
                    form_form_tpl="_auth_service_logon_form.tpl"
                    form_fields_tpl="_logon_login_form_fields.tpl"
                    form_support_tpl="_logon_login_support.tpl"
                    form_outside_tpl="_logon_login_outside.tpl"
                    style_boxed=0
                    style_width="300px"
                    logon_context=""
                %}

            </div>

        {% endif %}

    {% else %}

        <h1>{_ Invalid token _}</h1>
        <p>{_ The token is unknown or already used. Go back and try again. _}</p>

    {% endif %}

    {% javascript %}
        {# Hide remember-me, we always show a logon form anyway #}
        $("input[name='rememberme']").parent().hide();

        {# Prevent reload of page after session changed #}
        pubzub.subscribe("~pagesession/session", function() { });
    {% endjavascript %}

{% endblock %}

