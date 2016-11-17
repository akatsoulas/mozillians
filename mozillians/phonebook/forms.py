import re
from cStringIO import StringIO
from datetime import datetime

from django import forms
from django.conf import settings
from django.contrib.auth.models import User
from django.core.files.uploadedfile import UploadedFile
from django.forms.models import BaseInlineFormSet, inlineformset_factory
from django.forms.widgets import RadioSelect
from django.utils.translation import ugettext as _, ugettext_lazy as _lazy

import django_filters
import happyforms
from dal import autocomplete, fields as dal_fields
from nocaptcha_recaptcha.fields import NoReCaptchaField
from PIL import Image

from mozillians.api.models import APIv2App
from mozillians.groups.models import Skill
from mozillians.phonebook.models import Invite
from mozillians.phonebook.validators import validate_username
from mozillians.phonebook.widgets import MonthYearWidget
from mozillians.users import get_languages_for_locale
from mozillians.users.models import AbuseReport, ExternalAccount, Language, UserProfile


REGEX_NUMERIC = re.compile('\d+', re.IGNORECASE)


class ExternalAccountForm(happyforms.ModelForm):
    class Meta:
        model = ExternalAccount
        fields = ['type', 'identifier', 'privacy']

    def clean(self):
        cleaned_data = super(ExternalAccountForm, self).clean()
        identifier = cleaned_data.get('identifier')
        account_type = cleaned_data.get('type')

        if account_type and identifier:
            # If the Account expects an identifier and user provided a
            # full URL, try to extract the identifier from the URL.
            url = ExternalAccount.ACCOUNT_TYPES[account_type].get('url')
            if url and identifier.startswith('http'):
                url_pattern_re = url.replace('{identifier}', '(.+)')
                identifier = identifier.rstrip('/')
                url_pattern_re = url_pattern_re.rstrip('/')
                match = re.match(url_pattern_re, identifier)
                if match:
                    identifier = match.groups()[0]

            validator = ExternalAccount.ACCOUNT_TYPES[account_type].get('validator')
            if validator:
                identifier = validator(identifier)

            cleaned_data['identifier'] = identifier

        return cleaned_data


AccountsFormset = inlineformset_factory(UserProfile, ExternalAccount,
                                        form=ExternalAccountForm, extra=1)


class AlternateEmailForm(happyforms.ModelForm):
    class Meta:
        model = ExternalAccount
        fields = ['privacy']


AlternateEmailFormset = inlineformset_factory(UserProfile, ExternalAccount,
                                              form=AlternateEmailForm, extra=0)


class EmailPrivacyForm(happyforms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['privacy_email']


class SearchForm(happyforms.Form):
    q = forms.CharField(required=False, max_length=140)
    limit = forms.IntegerField(
        widget=forms.HiddenInput, required=False, min_value=1,
        max_value=settings.ITEMS_PER_PAGE)
    include_non_vouched = forms.BooleanField(
        label=_lazy(u'Include non-vouched'), required=False)

    def clean_limit(self):
        limit = self.cleaned_data['limit'] or settings.ITEMS_PER_PAGE
        return limit


def filter_vouched(qs, choice):
    if choice == SearchFilter.CHOICE_ONLY_VOUCHED:
        return qs.filter(is_vouched=True)
    elif choice == SearchFilter.CHOICE_ONLY_UNVOUCHED:
        return qs.filter(is_vouched=False)
    return qs


class SearchFilter(django_filters.FilterSet):
    CHOICE_ONLY_VOUCHED = 'yes'
    CHOICE_ONLY_UNVOUCHED = 'no'
    CHOICE_ALL = 'all'

    CHOICES = (
        (CHOICE_ONLY_VOUCHED, _lazy('Vouched')),
        (CHOICE_ONLY_UNVOUCHED, _lazy('Unvouched')),
        (CHOICE_ALL, _lazy('All')),
    )

    vouched = django_filters.ChoiceFilter(
        name='vouched', label=_lazy(u'Display only'), required=False,
        choices=CHOICES, action=filter_vouched)

    class Meta:
        model = UserProfile
        fields = ['vouched', 'skills', 'groups', 'timezone']

    def __init__(self, *args, **kwargs):
        super(SearchFilter, self).__init__(*args, **kwargs)
        self.filters['timezone'].field.choices.insert(0, ('', _lazy(u'All timezones')))


class UserForm(happyforms.ModelForm):
    """Instead of just inhereting form a UserProfile model form, this
    base class allows us to also abstract over methods that have to do
    with the User object that need to exist in both Registration and
    Profile.

    """
    username = forms.CharField(label=_lazy(u'Username'))

    class Meta:
        model = User
        fields = ['username']

    def clean_username(self):
        username = self.cleaned_data['username']
        if not username:
            return self.instance.username

        # Don't be jacking somebody's username
        # This causes a potential race condition however the worst that can
        # happen is bad UI.
        if (User.objects.filter(username=username).
                exclude(pk=self.instance.id).exists()):
            raise forms.ValidationError(_(u'This username is in use. Please try'
                                          u' another.'))

        # No funky characters in username.
        if not re.match(r'^[\w.@+-]+$', username):
            raise forms.ValidationError(_(u'Please use only alphanumeric'
                                          u' characters'))

        if not validate_username(username):
            raise forms.ValidationError(_(u'This username is not allowed, '
                                          u'please choose another.'))
        return username


class BasicInformationForm(happyforms.ModelForm):
    photo = forms.ImageField(label=_lazy(u'Profile Photo'), required=False)
    photo_delete = forms.BooleanField(label=_lazy(u'Remove Profile Photo'),
                                      required=False)

    class Meta:
        model = UserProfile
        fields = ('photo', 'privacy_photo', 'full_name', 'privacy_full_name',
                  'full_name_local', 'privacy_full_name_local', 'bio', 'privacy_bio',)
        widgets = {'bio': forms.Textarea()}

    def clean_photo(self):
        """Clean possible bad Image data.

        Try to load EXIF data from image. If that fails, remove EXIF
        data by re-saving the image. Related bug 919736.

        """
        photo = self.cleaned_data['photo']
        if photo and isinstance(photo, UploadedFile):
            image = Image.open(photo.file)
            try:
                image._get_exif()
            except (AttributeError, IOError, KeyError, IndexError):
                cleaned_photo = StringIO()
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                image.save(cleaned_photo, format='JPEG', quality=95)
                photo.file = cleaned_photo
                photo.size = cleaned_photo.tell()
        return photo


class SkillCreateField(dal_fields.CreateModelFieldMixin, forms.ModelMultipleChoiceField):

    def create_value(self, value):
        """This is used to create a new Skill,
        if it doesn't already exist in the database.
        """
        skill, _created = Skill.objects.get_or_create(name=value)
        return skill.id

    def clean(self, value):
        """Custom clean method.

        Allow only certain characters when creating a new instance.
        """
        new_value = ''
        # value is a list of strings (IDs of saved objects or string values)
        # eg ['1', '9', 'foo']
        for item in value:

            try:
                # Try to validate the list. If the given list has not only
                # PK values, Django's _check_values in ModelMultipleChoiceField
                # will raise a ValidationError
                return super(SkillCreateField, self).clean(value)
            except forms.ValidationError as e:
                # catch the non-numberic value (eg 'foo')
                new_value = e.params.get('pk', None)

            if new_value:
                # Feed the value to the regex. If we have a match then create
                # a new Skill in the db and add the corresponding PK to the list of
                # IDS. Else we have an invalid input, remove it and raise a ValidationError
                if re.match(r'^[a-zA-Z0-9 +.:,-]*$', new_value):
                    new_db_item = self.create_value(new_value)
                    value[value.index(new_value)] = new_db_item
                else:
                    value.pop(value.index(new_value))
                    msg = _(u'Skills can only contain latin characters and +.:-.')
                    self.error_messages['invalid_choice'] = msg
                    raise forms.ValidationError(self.error_messages['invalid_choice'],
                                                code='invalid_choice')

        return super(SkillCreateField, self).clean(value)


class SkillsForm(happyforms.ModelForm):
    skills = SkillCreateField(
        required=False,
        queryset=Skill.objects.all(),
        widget=autocomplete.ModelSelect2Multiple(url='groups:skills-autocomplete'))

    def __init__(self, *args, **kwargs):
        super(SkillsForm, self).__init__(*args, **kwargs)
        self.fields['skills'].help_text = (u'Start typing to add a skill (example: Python, '
                                           u'javascript, Graphic Design, User Research)')

    def save(self, *args, **kwargs):
        """Save the data to profile."""
        self.instance.set_membership(Skill, self.cleaned_data['skills'])
        super(SkillsForm, self).save(*args, **kwargs)

    class Meta:
        model = UserProfile
        fields = ('privacy_skills', 'skills',)


class LanguagesPrivacyForm(happyforms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ('privacy_languages',)


class LocationForm(happyforms.ModelForm):
    lat = forms.FloatField(widget=forms.HiddenInput)
    lng = forms.FloatField(widget=forms.HiddenInput)
    savecountry = forms.BooleanField(label=_lazy(u'Required'),
                                     initial=True, required=False,
                                     widget=forms.CheckboxInput(attrs={'disabled': 'disabled'}))
    saveregion = forms.BooleanField(label=_lazy(u'Save'), required=False, show_hidden_initial=True)
    savecity = forms.BooleanField(label=_lazy(u'Save'), required=False, show_hidden_initial=True)

    class Meta:
        model = UserProfile
        fields = ('timezone', 'privacy_timezone', 'privacy_geo_city', 'privacy_geo_region',
                  'privacy_geo_country',)

    def clean(self):
        # If lng/lat were provided, make sure they point at a country somewhere...
        if self.cleaned_data.get('lat') is not None and self.cleaned_data.get('lng') is not None:
            # We only want to call reverse_geocode if some location data changed.
            if ('lat' in self.changed_data or 'lng' in self.changed_data or
                    'saveregion' in self.changed_data or 'savecity' in self.changed_data):
                self.instance.lat = self.cleaned_data['lat']
                self.instance.lng = self.cleaned_data['lng']
                self.instance.reverse_geocode()
                if not self.instance.geo_country:
                    error_msg = _('Location must be inside a country.')
                    self.errors['savecountry'] = self.error_class([error_msg])
                    del self.cleaned_data['savecountry']
                # If the user doesn't want their region/city saved, respect it.
                if not self.cleaned_data.get('saveregion'):
                    if not self.cleaned_data.get('savecity'):
                        self.instance.geo_region = None
                    else:
                        error_msg = _('Region must also be saved if city is saved.')
                        self.errors['saveregion'] = self.error_class([error_msg])

                if not self.cleaned_data.get('savecity'):
                    self.instance.geo_city = None
        else:
            self.errors['location'] = self.error_class([_('Search for your country on the map.')])
            self.errors['savecountry'] = self.error_class([_('Country cannot be empty.')])
            del self.cleaned_data['savecountry']

        return self.cleaned_data


class ContributionForm(happyforms.ModelForm):
    date_mozillian = forms.DateField(
        required=False,
        label=_lazy(u'When did you get involved with Mozilla?'),
        widget=MonthYearWidget(years=range(1998, datetime.today().year + 1),
                               required=False))

    class Meta:
        model = UserProfile
        fields = ('title', 'privacy_title',
                  'date_mozillian', 'privacy_date_mozillian',
                  'story_link', 'privacy_story_link',)


class TshirtForm(happyforms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ('tshirt', 'privacy_tshirt',)


class GroupsPrivacyForm(happyforms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ('privacy_groups',)


class IRCForm(happyforms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ('ircname', 'privacy_ircname',)


class DeveloperForm(happyforms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ('allows_community_sites', 'allows_mozilla_sites',)


class BaseLanguageFormSet(BaseInlineFormSet):

    def __init__(self, *args, **kwargs):
        self.locale = kwargs.pop('locale', 'en')
        super(BaseLanguageFormSet, self).__init__(*args, **kwargs)

    def add_fields(self, form, index):
        super(BaseLanguageFormSet, self).add_fields(form, index)
        choices = [('', '---------')] + get_languages_for_locale(self.locale)
        form.fields['code'].choices = choices

    class Meta:
        models = Language
        fields = ['code']


LanguagesFormset = inlineformset_factory(UserProfile, Language,
                                         formset=BaseLanguageFormSet,
                                         extra=1, fields='__all__')


class EmailForm(happyforms.Form):
    email = forms.EmailField(label=_lazy(u'Email'))

    def clean_email(self):
        email = self.cleaned_data['email']
        if (User.objects.exclude(pk=self.initial['user_id']).filter(email=email).exists()):
            raise forms.ValidationError(_(u'Email is currently associated with another user.'))
        return email

    def email_changed(self):
        return self.cleaned_data['email'] != self.initial['email']


class RegisterForm(BasicInformationForm, LocationForm):
    optin = forms.BooleanField(
        widget=forms.CheckboxInput(attrs={'class': 'checkbox'}),
        required=True)
    captcha = NoReCaptchaField()

    class Meta:
        model = UserProfile
        fields = ('photo', 'full_name', 'timezone', 'privacy_photo', 'privacy_full_name', 'optin',
                  'privacy_timezone', 'privacy_geo_city', 'privacy_geo_region',
                  'privacy_geo_country',)


class VouchForm(happyforms.Form):
    """Vouching is captured via a user's id and a description of the reason for vouching."""
    description = forms.CharField(
        label=_lazy(u'Provide a reason for vouching with relevant links'),
        widget=forms.Textarea(attrs={'rows': 10, 'cols': 20, 'maxlength': 500}),
        max_length=500,
        error_messages={'required': _(u'You must enter a reason for vouching for this person.')}
    )


class InviteForm(happyforms.ModelForm):
    message = forms.CharField(
        label=_lazy(u'Personal message to be included in the invite email'),
        required=False, widget=forms.Textarea(),
    )
    recipient = forms.EmailField(label=_lazy(u"Recipient's email"))

    def clean_recipient(self):
        recipient = self.cleaned_data['recipient']
        if User.objects.filter(email=recipient,
                               userprofile__is_vouched=True).exists():
            raise forms.ValidationError(
                _(u'You cannot invite someone who has already been vouched.'))
        return recipient

    class Meta:
        model = Invite
        fields = ['recipient']


class APIKeyRequestForm(happyforms.ModelForm):

    class Meta:
        model = APIv2App
        fields = ('name', 'description', 'url',)


class AbuseReportForm(happyforms.ModelForm):

    class Meta:
        model = AbuseReport
        fields = ('type',)
        widgets = {
            'type': RadioSelect
        }
        labels = {
            'type': _(u'What would you like to report?')
        }
