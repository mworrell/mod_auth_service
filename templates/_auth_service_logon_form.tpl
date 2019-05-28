<iframe src="/lib/images/spinner.gif" id="logonTarget" name="logonTarget" style="display:none"></iframe>

{% wire id="logon_form"
        type="submit"
        postback={logon auth_service_logon=q.token}
        delegate=`controller_logon`
%}
<form id="logon_form" method="post" action="postback" class="z_logon_form" target="logonTarget">
    <input type="hidden" name="page" value="{{ page|escape }}" />
    <input type="hidden" name="handler" value="username" />

    {% include form_fields_tpl %}
</form>

{% wire action={unmask target="logon_form"} %}

<p class="z-logon-support">
    <a href="#" id="{{ #back }}">&lt; {_ Go back _}</a>
</p>
{% wire id=#back action={redirect back} %}
