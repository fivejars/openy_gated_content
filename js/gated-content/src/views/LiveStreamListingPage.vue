<template>
  <div class="live-stream-listing-page">
    <EventListing
      :title="config.components.live_stream.title"
      :withDateFilter="true"
      :msg="emptyMsg"
    />
  </div>
</template>

<script>
import EventListing from '@/components/event/EventListing.vue';
import { SettingsMixin } from '@/mixins/SettingsMixin';

export default {
  name: 'LiveStreamListingPage',
  mixins: [SettingsMixin],
  components: {
    EventListing,
  },
  computed: {
    emptyMsg() {
      return this.config.live_stream_empty_text === ''
        ? 'Events not found.' : this.config.live_stream_empty_text;
    },
  },
};
</script>
