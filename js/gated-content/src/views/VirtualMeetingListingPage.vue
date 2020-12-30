<template>
  <div class="live-stream-listing-page">
    <EventListing
      :title="config.components.virtual_meeting.title"
      :eventType="'virtual_meeting'"
      :withDateFilter="true"
      :msg="emptyMsg"
    />
  </div>
</template>

<script>
import EventListing from '@/components/event/EventListing.vue';
import { SettingsMixin } from '@/mixins/SettingsMixin';

export default {
  name: 'VirtualMeetingListingPage',
  mixins: [SettingsMixin],
  components: {
    EventListing,
  },
  computed: {
    emptyMsg() {
      return this.config.virtual_meeting_empty_text === ''
        ? 'Events not found.' : this.config.virtual_meeting_empty_text;
    },
  },
};
</script>
