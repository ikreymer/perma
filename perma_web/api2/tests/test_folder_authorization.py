from .utils import ApiResourceTransactionTestCase
from api.resources import FolderResource
from perma.models import LinkUser, Folder


class FolderAuthorizationTestCase(ApiResourceTransactionTestCase):

    resource = FolderResource

    fixtures = ['fixtures/users.json',
                'fixtures/folders.json',
                'fixtures/archive.json',
                'fixtures/api_keys.json']

    def setUp(self):
        super(FolderAuthorizationTestCase, self).setUp()

        self.admin_user = LinkUser.objects.get(pk=1)
        self.registrar_user = LinkUser.objects.get(pk=2)
        self.org_user = LinkUser.objects.get(pk=3)
        self.regular_user = LinkUser.objects.get(pk=4)

        self.empty_root_folder = Folder.objects.get(pk=22)
        self.nonempty_root_folder = Folder.objects.get(pk=25)
        self.regular_user_empty_child_folder = Folder.objects.get(pk=29)
        self.regular_user_nonempty_child_folder = Folder.objects.get(pk=30)

        self.third_journal_shared_folder = Folder.objects.get(pk=31)

        self.test_journal_shared_folder = Folder.objects.get(pk=27)
        self.test_journal_subfolder_with_link_a = Folder.objects.get(pk=34)
        self.test_journal_subfolder_with_link_b = Folder.objects.get(pk=35)


        # self.list_url = self.url_base + '/user/folders'
        # self.nested_url = "{0}/{1}/folders".format(self.list_url, self.nonempty_root_folder.pk)
        self.list_url = "{0}/{1}".format(self.url_base, FolderResource.Meta.resource_name)
        #self.nested_url = "{0}/folders".format(self.detail_url(self.nonempty_root_folder))

    # helpers

    def nested_url(self, obj):
        return self.detail_url(obj)+"/folders"

    ############
    # Creating #
    ############

    def test_should_allow_logged_in_user_to_create(self):
        self.successful_post(self.nested_url(self.regular_user.root_folder),
                             user=self.regular_user,
                             data={'name': 'Test Folder'})

    def test_should_reject_folder_create_without_parent(self):
        self.rejected_post(self.list_url,
                           user=self.regular_user,
                           expected_status_code=400,
                           data={'name': 'Test Folder'})

    def test_should_reject_create_from_logged_out_user(self):
        self.rejected_post(self.nested_url(self.regular_user.root_folder),
                           data={'name': 'Test Folder'})


    def test_should_reject_create_from_user_without_access_to_parent(self):
        self.rejected_post(self.nested_url(self.regular_user.root_folder),
                           user=self.org_user,
                           expected_status_code=403,
                           data={'name': 'Test Folder'})

    ###########
    # Viewing #
    ###########

    def test_should_allow_folder_owner_to_view(self):
        self.successful_get(self.detail_url(self.nonempty_root_folder), user=self.regular_user)

    def test_should_allow_member_of_folders_registrar_to_view(self):
        self.successful_get(self.detail_url(self.test_journal_shared_folder), user=self.registrar_user)

    def test_should_allow_member_of_folders_org_to_view(self):
        self.successful_get(self.detail_url(self.test_journal_shared_folder), user=self.org_user)

    def test_should_reject_view_from_user_lacking_owner_and_registrar_and_org_access(self):
        self.rejected_get(self.detail_url(self.test_journal_shared_folder),
                          user=self.regular_user,
                          expected_status_code=403)

    ############
    # Renaming #
    ############

    def test_should_allow_nonshared_nonroot_folder_owner_to_rename(self):
        self.successful_patch(self.detail_url(self.regular_user_nonempty_child_folder),
                              user=self.regular_user_nonempty_child_folder.created_by,
                              data={'name': 'A new name'})

    def test_should_reject_rename_from_user_lacking_owner_access(self):
        self.rejected_patch(self.detail_url(self.regular_user_nonempty_child_folder),
                            user=self.registrar_user,
                            expected_status_code=403,
                            data={'name': 'A new name'})

    def test_should_reject_rename_of_shared_folder_from_all_users(self):
        data = {'name': 'A new name'}
        url = self.detail_url(self.test_journal_shared_folder)

        self.rejected_patch(url, user=self.admin_user, data=data, expected_status_code=400)
        self.rejected_patch(url, user=self.registrar_user, data=data, expected_status_code=400)

    def test_should_reject_rename_of_root_folder_from_all_users(self):
        data = {'name': 'A new name'}
        self.rejected_patch(self.detail_url(self.admin_user.root_folder),
                            expected_status_code=400,
                            user=self.admin_user, data=data)

        self.rejected_patch(self.detail_url(self.registrar_user.root_folder),
                            expected_status_code=400,
                            user=self.registrar_user, data=data)

        self.rejected_patch(self.detail_url(self.regular_user.root_folder),
                            expected_status_code=400,
                            user=self.regular_user, data=data)

    ##########
    # Moving #
    ##########

    def successful_folder_move(self, user, parent_folder, child_folder):
        self.successful_put(
            "{0}/folders/{1}".format(self.detail_url(parent_folder), child_folder.pk),
            user=user
        )

        # Make sure move worked
        child_folder.refresh_from_db()
        self.assertEquals(child_folder.parent_id, parent_folder.id)

    def rejected_folder_move(self, user, parent_folder, child_folder, expected_status_code=401):
        original_parent_id = child_folder.parent_id

        self.rejected_put(
            "{0}/folders/{1}".format(self.detail_url(parent_folder), child_folder.pk),
            expected_status_code=expected_status_code,
            user=user
        )

        # Make sure move didn't work
        child_folder.refresh_from_db()
        self.assertEquals(child_folder.parent_id, original_parent_id)
        self.assertNotEqual(child_folder.parent_id, parent_folder.id)

    def test_should_allow_move_to_new_folder_via_put(self):
        # PUT /folders/:new_parent_id/folders/:id
        self.successful_folder_move(self.regular_user_empty_child_folder.owned_by, self.regular_user_nonempty_child_folder, self.regular_user_empty_child_folder)

    def test_should_allow_move_to_new_folder_via_patch(self):
        # PATCH /folders/:id {'parent': new_parent_id}
        child_folder = self.regular_user_empty_child_folder
        parent_folder = self.regular_user_nonempty_child_folder
        self.successful_patch(self.detail_url(child_folder),
                              data={"parent": parent_folder.pk},
                              user=child_folder.owned_by)
        child_folder.refresh_from_db()
        self.assertEquals(child_folder.parent_id, parent_folder.pk)

    def test_should_allow_member_of_folders_registrar_to_move_to_new_parent(self):
        self.successful_folder_move(self.registrar_user, self.registrar_user.root_folder, self.test_journal_subfolder_with_link_b)

    def test_should_allow_member_of_folders_org_to_move_to_new_parent(self):
        self.successful_folder_move(self.org_user, self.org_user.root_folder, self.test_journal_subfolder_with_link_b)

    def test_should_reject_move_to_parent_to_which_user_lacks_access(self):
        self.rejected_folder_move(self.regular_user,
                                  self.org_user.root_folder,
                                  self.regular_user_empty_child_folder,
                                  expected_status_code=403)

    def test_should_reject_move_from_user_lacking_owner_and_registrar_and_org_access(self):
        self.rejected_folder_move(self.regular_user,
                                  self.regular_user.root_folder,
                                  self.test_journal_subfolder_with_link_b,
                                  expected_status_code=403)

    def test_should_reject_move_of_folder_into_its_own_subfolder(self):
        # move A into B ...
        self.successful_patch(self.detail_url(self.test_journal_subfolder_with_link_a),
                              data={"parent": self.test_journal_subfolder_with_link_b.pk},
                              user=self.org_user)

        # ... then try to move B into A
        self.rejected_patch(self.detail_url(self.test_journal_subfolder_with_link_b),
                            data={"parent": self.test_journal_subfolder_with_link_a.pk},
                            expected_status_code=400,
                            expected_data={"parent": ["A node may not be made a child of any of its descendants."]},
                            user=self.org_user)

    def test_should_reject_move_of_folder_into_itself(self):
        self.rejected_patch(self.detail_url(self.test_journal_subfolder_with_link_b),
                            data={"parent": self.test_journal_subfolder_with_link_b.pk},
                            expected_status_code=400,
                            expected_data={"parent": ["A node may not be made a child of itself."]},
                            user=self.org_user)

    def test_should_reject_move_of_org_shared_folder(self):
        self.rejected_folder_move(self.registrar_user, self.registrar_user.root_folder,
                                  self.test_journal_shared_folder,
                                  expected_status_code=400)

    def test_should_reject_move_of_user_root_folder(self):
        self.rejected_folder_move(self.registrar_user, self.test_journal_shared_folder,
                                  self.registrar_user.root_folder,
                                  expected_status_code=400)

    def test_should_reject_move_to_blank_folder(self):
        self.rejected_patch(self.detail_url(self.regular_user_empty_child_folder),
                            user=self.regular_user_empty_child_folder.owned_by,
                            data={'parent':None},
                            expected_status_code=400,
                            expected_data={"parent": ["This field may not be null."]})


    ############
    # Deleting #
    ############

    def test_should_allow_folder_owner_to_delete(self):
        self.successful_delete(self.detail_url(self.regular_user_empty_child_folder),
                               user=self.regular_user_empty_child_folder.created_by)

    def test_should_reject_delete_from_user_lacking_owner_and_registrar_and_org_access(self):
        self.rejected_delete(self.detail_url(self.regular_user_empty_child_folder),
                             expected_status_code=403,
                             user=self.org_user)

    def test_reject_delete_of_shared_folder(self):
        self.rejected_delete(self.detail_url(self.test_journal_shared_folder),
                             expected_status_code=400,
                             expected_data={"error": ["Top-level folders cannot be deleted."]},
                             user=self.org_user)

    def test_reject_delete_of_root_folder(self):
        self.rejected_delete(self.detail_url(self.org_user.root_folder),
                             expected_status_code=400,
                             expected_data={"error": ["Top-level folders cannot be deleted."]},
                             user=self.org_user)

    def test_reject_delete_of_nonempty_folder(self):
        self.rejected_delete(self.detail_url(self.test_journal_subfolder_with_link_b),
                             expected_status_code=400,
                             expected_data={"error": ["Folders can only be deleted if they are empty."]},
                             user=self.org_user)

